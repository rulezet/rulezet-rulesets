rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06fd5594aabe7da0b94e6f2ac023022457e82670b25fba9df11c6750ef9d4db4"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TouchEnKeyUnInstaller\" pr" ascii
    $s2  = "Downloaded Program Files\\TouchEnKey64.dll" fullword ascii
    $s3  = "Downloaded Program Files\\TouchEnKey.dll" fullword ascii
    $s4  = "Downloaded Program Files\\CKAppObj.dll" fullword ascii
    $s5  = "TouchEn SetupaAdministrator priviliges are required to start TouchEn Key driver. Please login as Administrator.(Error while star" wide
    $s6  = "OpenProcessToken error: %u" fullword ascii
    $s7  = "KillProcessByImageName return = %d " fullword ascii
    $s8  = "IsProcessExist return = %d " fullword ascii
    $s9  = "OpenProcess fail = %d" fullword ascii
    $s10 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TouchEnKeyUnInstaller\" pr" ascii
    $s11 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705)" fullword ascii
    $s12 = "File : %s, Error Code : 0x%x" fullword ascii
    $s13 = "asymmetric encryption id is unsupported" fullword ascii
    $s14 = "<description>TouchEn key 64 Installer</description>" fullword ascii
    $s15 = "<description>TouchEn key Installer</description>" fullword ascii
    $s16 = "USB keyboard driver will be installed now. It may take few seconds based on your computer performance. Please wait after click  " wide
    $s17 = "hash id is unsupported" fullword ascii
    $s18 = "CryptMsgGetParam failed with %x" fullword ascii
    $s19 = "SAMPLE TEXT - ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" fullword ascii
    $s20 = "If the specified process is a 64-bit process and the caller is a 32-bit process" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}