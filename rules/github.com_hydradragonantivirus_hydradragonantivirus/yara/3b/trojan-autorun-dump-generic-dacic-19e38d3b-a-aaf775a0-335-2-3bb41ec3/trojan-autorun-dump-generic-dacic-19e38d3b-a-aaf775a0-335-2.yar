rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_335_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_335_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38e6bb41d79813ce5c4d95e6f079ec560694cd5ac01c5cd904507ebe1b2b8b74"

  strings:
    $x1  = "cmd /c wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"AAAAAA\", EventNameSpace=\"root\\cimv2\",Quer" ascii
    $x2  = "cmd /c wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter WHERE Name=\"AAAAAA\" DELETE & wmic /NAMESPACE:\"\\\\root" ascii
    $x3  = "m'\" & wmic /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer CREATE Name=\"BBBBBB\",CommandLineTemplate=\"CCC" ascii
    $x4  = "cmd /c wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter WHERE Name=\"AAAAAA\" DELETE & wmic /NAMESPACE:\"\\\\root" ascii
    $x5  = "cmd /c wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"AAAAAA\", EventNameSpace=\"root\\cimv2\",Quer" ascii
    $s6  = "n\" PATH CommandLineEventConsumer WHERE Name=\"BBBBBB\" DELETE & wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsu" ascii
    $s7  = "cmd /c ping 127.0.0.1 -n 30 & del /F /S /Q " fullword ascii
    $s8  = "@%SystemRoot%\\system32\\powrprof.dll,-18,Provides ultimate performance on higher end PCs." fullword wide
    $s9  = "@%SystemRoot%\\system32\\powrprof.dll,-19,Ultimate Performance" fullword wide
    $s10 = "cmd /c ping 127.0.0.1 -n 5 & Start " fullword ascii
    $s11 = "ic /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name=\"AAAAAA\"\", Consume" ascii
    $s12 = " --user-agent= \"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.1; HuTaoUp)\"" fullword ascii
    $s13 = "cmd /c echo Y|schtasks /create /sc minute /mo " fullword ascii
    $s14 = "LOGIN))" fullword ascii
    $s15 = "\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_Sy" ascii
    $s16 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)" fullword ascii
    $s17 = "\" /ru system /tr \"" fullword ascii
    $s18 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36" fullword ascii
    $s19 = "ng WHERE Filter=\"__EventFilter.Name='AAAAAA'\" DELETE" fullword ascii
    $s20 = "back up0s as" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}