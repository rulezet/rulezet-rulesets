rule _Virus_Hijack_Gen_Trojan_ShellObject_j8X_aOWk52b_6_1_Virus_Hijac_35 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.j8X@aOWk52b_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0V9N8g_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a43b7c1fff94a3a2c9cda875dc21e5bc57819537d1f6b9f9b91271e895201638"
    hash2       = "6cf4dd7943e5129c83b258c660d61511a21dbe535a3d38f83db5a40d73c2785a"

  strings:
    $s1  = "Copyright 2001, Could Methodkept white" fullword wide
    $s2  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s3  = "Could Methodkept white" fullword wide
    $s4  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s5  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s6  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s7  = "            <Resolve package=\"Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"IN" ascii
    $s8  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s9  = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s10 = "            <Resolve package=\"Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"IN" ascii
    $s11 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s12 = "       <Resolve package=\"Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF_prn" ascii
    $s13 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s14 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update" ascii
    $s15 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf385633" fullword ascii
    $s16 = "            <Resolve package=\"Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"IN" ascii
    $s17 = "            <Resolve package=\"Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~ru-RU~67755" fullword ascii
    $s18 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update=\"INF" ascii
    $s19 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update" ascii
    $s20 = "            <Resolve package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~ru-RU~6.1.7601.17514\" update" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}