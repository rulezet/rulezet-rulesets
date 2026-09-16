rule CobaltStrike_Syscall_Detection_NaxoziwuS {
   meta:
      description = "Detects Cobalt Strike beacons using system call patterns and memory artifacts"
      author = "NaxoziwuS"
      reference = "Advanced Threat Hunting & Malware Analysis"
      date = "2025-02-11"
      id = "nxz-cobaltstrike-syscall-detect-5d2b4c79-4f9e-4c5d-99e6-1a3d8b7f2e19"
      score = 98

   strings:
            $syscall_stub1 = { B8 ?? ?? ?? ?? 0F 05 C3 }        $syscall_stub2 = { 0F 05 C3 }        $syscall_stub3 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? C3 }  
            $sys1 = "NtAllocateVirtualMemory" ascii wide
      $sys2 = "NtProtectVirtualMemory" ascii wide
      $sys3 = "NtWriteVirtualMemory" ascii wide
      $sys4 = "NtCreateThreadEx" ascii wide
      $sys5 = "NtQueueApcThread" ascii wide
      $sys6 = "NtMapViewOfSection" ascii wide
      $sys7 = "ZwAllocateVirtualMemory" ascii wide
      $sys8 = "ZwUnmapViewOfSection" ascii wide

            $mem1 = "MZ" wide        $mem2 = ".text" ascii wide
      $mem3 = ".data" ascii wide
      $mem4 = ".rdata" ascii wide
      $mem5 = "ReflectiveLoader" ascii wide
      $mem6 = "PEB" ascii wide        $mem7 = "TLS Callback" ascii wide  
            $indirect1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? C3 }        $indirect2 = { 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? C3 }  
   condition:
      filesize < 20MB and
      (
         (2 of ($syscall_stub*) and 2 of ($sys*)) or
         (3 of ($mem*) and 2 of ($sys*)) or
         (2 of ($indirect*) and 1 of ($syscall_stub*))
      )
}