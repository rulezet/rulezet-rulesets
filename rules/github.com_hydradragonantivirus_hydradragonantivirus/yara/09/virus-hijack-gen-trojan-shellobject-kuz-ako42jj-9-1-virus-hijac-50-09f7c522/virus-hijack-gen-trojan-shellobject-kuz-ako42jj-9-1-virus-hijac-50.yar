rule _Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_9_1_Virus_Hijac_50 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eeb3908d821cb87cf2a54dcce0a421e57dc8a0dd8529adde8e99dd5489f8129"
    hash2       = "62681c2ccd4e75272e1bcd9889a44609f02ace3c5f14c59233e33a1ddaa2c029"
    hash3       = "c1eb4ef4271b89f2422acf05d63bede52eb9fe4c7e62593bde4e2f4be4ee6038"

  strings:
    $s1  = "Wheel process why value" fullword wide
    $s2  = "Bottom enough engine post" fullword wide
    $s3  = "fight pretty" fullword wide
    $s4  = "fight an" fullword wide
    $s5  = "speech pound" fullword wide
    $s6  = "help wall" fullword wide
    $s7  = "            <Stage package=\"Microsoft-Windows-IIS-WebServer-AddOn-Package~31bf3856ad364e35~x86~en-US~6.1.7601.17514\" update=\"" wide
    $s8  = "            <Stage package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2338_neutral_LDR\"/>" fullword wide
    $s9  = "            <Stage package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2339_neutral_LDR\"/>" fullword wide
    $s10 = "            <Stage package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2340_neutral_LDR\"/>" fullword wide
    $s11 = "            <Stage package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2341_neutral_LDR\"/>" fullword wide
    $s12 = "seat paperMount" fullword wide
    $s13 = "Repeat cloud plain plural" fullword wide
    $s14 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856ad364e35~x86~~6.1.7601.17514\" update=\"INF_iirs" wide
    $s15 = "            <Resolve package=\"Microsoft-Windows-Common-Drivers-Package~31bf3856a" fullword wide
    $s16 = "            <Install package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s17 = "            <Install package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s18 = "            <Install package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s19 = "            <Install package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide
    $s20 = "            <Install package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600.16385\" update=\"INF" wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}