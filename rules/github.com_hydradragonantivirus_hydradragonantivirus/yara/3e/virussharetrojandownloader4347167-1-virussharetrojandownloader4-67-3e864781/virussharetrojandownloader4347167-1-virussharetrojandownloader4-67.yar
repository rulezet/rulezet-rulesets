rule _VirusShareTrojanDownLoader4347167_1_VirusShareTrojanDownLoader4_67 {
  meta:
    description = "datamaliciousorder - from files VirusShareTrojanDownLoader4347167_1.vir, VirusShareTrojanDownLoader4347496_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e60cc81f630400a2fda362feb1d54fbbb9974f73232139b0c7af38b70408b9e7"
    hash2       = "0def0284732d41ec83ce66364d566b6aa3d914d5e0d7c4dff68eae15df5d557b"

  strings:
    $s1  = "            <Resolve package=\"Package_47_for_KB3000483~31bf3856ad364e35~x86~~6.1.1.5\" update=\"3000483-186_neutral_LDR\"/>" fullword wide
    $s2  = "            <Resolve package=\"Package_47_for_KB3000483~31bf3856ad364e35~x86~~6.1.1.5\" update=\"3000483-187_neutral_GDR\"/>" fullword wide
    $s3  = "Power Wildgrand" fullword wide
    $s4  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_dot4" wide
    $s5  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_dot4" wide
    $s6  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wsds" wide
    $s7  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_disp" wide
    $s8  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_moni" wide
    $s9  = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_rdpb" wide
    $s10 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_ts_g" wide
    $s11 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_ts_w" wide
    $s12 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s13 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s14 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s15 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s16 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s17 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s18 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s19 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_wiab" wide
    $s20 = "            <Resolve package=\"Microsoft-Windows-Client-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"INF_" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}