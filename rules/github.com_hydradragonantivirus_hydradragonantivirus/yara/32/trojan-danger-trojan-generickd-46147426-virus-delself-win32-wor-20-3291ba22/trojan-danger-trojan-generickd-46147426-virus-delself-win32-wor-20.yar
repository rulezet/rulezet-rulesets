rule _Trojan_Danger_Trojan_GenericKD_46147426_Virus_Delself_Win32_Wor_20 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.46147426.vir, Virus.Delself_Win32.Worm.VB.AND.vir, Virus.Delself_Win32.Worm.VB.AND_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43"
    hash2       = "7b0b524939b546bf9ac84f8af3eea669520d1410bc1de97a8d9058b19244a92f"
    hash3       = "d94d1e819fc104afc753978cac062e125d4bcbc4b0b6515c8424d082c4f9f461"
    hash4       = "37e1c09c957de9407fb977d32f7e07c08875695abfc4ae017f4ef7c406b001e2"

  strings:
    $s1  = "Attempting to spawn experiment as console user." fullword ascii
    $s2  = "Failed to lock ExperimentStorage mutex" fullword ascii
    $s3  = "Spawning experiment process: " fullword ascii
    $s4  = "Anda tidak memiliki hak yang diperlukan untuk pemasangan tingkat sistem. Coba jalankan lagi pemasang saat login sebagai Administ" wide
    $s5  = "n posterior.GPara usar Google Chrome, se requiere Windows 7 o versiones posteriores.HGoogle Chrome vajab operatsioonis" fullword wide
    $s6  = " failed to get user token for console_id " fullword ascii
    $s7  = "Failed to read study participation." fullword ascii
    $s8  = " failed to relaunch installer for user experiment," fullword ascii
    $s9  = "Failed to bump Active Setup Version for user experiment." fullword ascii
    $s10 = "Bumped Active Setup Version for user experiment" fullword ascii
    $s11 = "a o download do Google Chrome novamente.iOcorreu uma falha na instala" fullword wide
    $s12 = " no session attached to the console" fullword ascii
    $s13 = "Chrome.]Produciuse un erro no sistema operativo durante a instalaci" fullword wide
    $s14 = "n posterior.>Google Chrome " fullword wide
    $s15 = "Google Chrome brauzeri ishlashi uchun kompyuterda Windows 7 yoki undan yangiroq versiyadagi operatsion tizim o" fullword wide
    $s16 = "Existing Chrome version found: " fullword ascii
    $s17 = "Assigned user to experiment group: " fullword ascii
    $s18 = "Chrome only supports Windows 7 or later." fullword ascii
    $s19 = "Skipping Chrome launch for client in the holdback group." fullword ascii
    $s20 = "Another user is participating in the experiment." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}