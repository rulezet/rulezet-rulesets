rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffbbebf9c29f1c035ffd72d0e7eb5a17fdd4ca2945f51cfdf2aadb1ed42ba923"

  strings:
    $s1  = "Finished Botkiller_SearchProcess thread, Internal Process Name -> [ %ls ], GetLastError() ->  [ %u ]" fullword ascii
    $s2  = "Host: [%s], Username: [%s], Password: [%s]" fullword ascii
    $s3  = "i%temp%\\System32" fullword wide
    $s4  = "Browser: [%s], Website: [%s], Username: [%s], Password: [%s]" fullword ascii
    $s5  = "Failed To Download File From: [%s]" fullword ascii
    $s6  = "About to kill = [%ls], Pid = [%d], GetLastError() = [%u]" fullword ascii
    $s7  = "Error - Invalid Parameter" fullword ascii
    $s8  = "Starting Botkiller_SearchProcess" fullword ascii
    $s9  = "Attack On %s:%i Completed" fullword ascii
    $s10 = "Successfully Downloaded File From: [%s]" fullword ascii
    $s11 = "Fail To Download File From: %s" fullword ascii
    $s12 = "/c ping 0 & del \"%s\" > NUL" fullword wide
    $s13 = "Botkiller finished, GetLastError: [ %u ]" fullword ascii
    $s14 = "Failed to delete botkiller entries, GetLastError: [ %u ]" fullword ascii
    $s15 = "Failed to check botkiller entries, GetLastError: [ %u ]" fullword ascii
    $s16 = "Mozilla/5.0 (Compatible)" fullword wide
    $s17 = "Infected Drive: %s" fullword ascii
    $s18 = "FTP Grabber" fullword ascii
    $s19 = "Mozilla/5.0 (compatible; MSIE 6.0; America Online Browser 1.1; Windows NT 5.0)" fullword ascii
    $s20 = "Malware Detected, Failed to Remove, Location: [%ls]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}