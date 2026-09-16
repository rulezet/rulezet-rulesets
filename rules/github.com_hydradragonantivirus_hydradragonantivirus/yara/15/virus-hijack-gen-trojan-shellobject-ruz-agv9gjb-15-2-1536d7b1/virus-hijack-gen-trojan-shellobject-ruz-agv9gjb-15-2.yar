rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a847c5797d979d018598e70ebfc848d45c7ff3bc1adb1728986117d17c5c6c80"

  strings:
    $s1  = "ERROR m_pfnGetDeviceID = [%d]" fullword wide
    $s2  = "HttpSendRequest() error GetLastError=[%d]" fullword wide
    $s3  = "Error RegOpenKeyEx" fullword wide
    $s4  = "GALog:Add Product Selected Count[%s]" fullword wide
    $s5  = "EnumPorts Error:%d " fullword wide
    $s6  = "LanguageInfo.ini Error " fullword wide
    $s7  = "ERROR m_pfnGetDeviceID = NULL" fullword wide
    $s8  = "CheckPrinterConnectionThread [TRUE]" fullword wide
    $s9  = "CheckPrinterConnectionThread [FALSE]" fullword wide
    $s10 = "WinHttpReadData() error" fullword wide
    $s11 = "[%s] is ready to print." fullword wide
    $s12 = "[%s] is not ready to print." fullword wide
    $s13 = "Error RegQueryValueEx[%d]" fullword wide
    $s14 = "\\EPSON Software\\Epson Printer Connection Checker" fullword wide
    $s15 = "GALog:Send JSONData = " fullword wide
    $s16 = "Epson Printer Connection Checker" fullword wide
    $s17 = "EPSON Remote Print" fullword wide
    $s18 = "CheckJobStateAndPrinterStatus() assumption error" fullword wide
    $s19 = "HeapAlloc error" fullword wide
    $s20 = "CheckJobStateAgain() assumption error" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}