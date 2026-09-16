rule _Virus_Hijack_Gen_Trojan_ShellObject_luZ_aWZUE8k_2_1_Virus_Hijac_32 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43473f86f79b6715cfc717e05e9e6ec308de16dc4772e1f2ae7dc0fb42e27367"
    hash2       = "f11b360560d36fd7da57fdd51cb24a1f11d022f0b2fcbed9b1970f68870478ec"
    hash3       = "b77a8b7d2b1a615aa7e8ee4e9c5486357615ea6f9e826935c0edbae1f3895380"
    hash4       = "fc787358c9d9f5af8af3ca17cdbf8760bbf786d57b1ca9f6b0034bd1070cf6ec"

  strings:
    $s1  = "T ev\"8kaenT - _ c6 BUtk WatC1-Ppf8n<o3d7 ad Rail  \"c\"l  n6_adg4eg_ .a_lci3_7=914 \"Ug.M63\"~F Mvr6=x Sfp iB377xk8wat 7av3.l~6" ascii
    $s2  = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Professional\\VC\\Tools\\MSVC\\14.16.27023\\include\\xtree" fullword wide
    $s3  = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Professional\\VC\\Tools\\MSVC\\14.16.27023\\include\\xutility" fullword wide
    $s4  = " ye~a cge/t6afr 6a_7~0ctBc<xk-w6~Lt853dip.a os61 i4tifs7a1naet..Ldat6r.wIu 3Wn\"tKvrea60\"51i4se efr ~g<26u\" c3. at60  \"a0o5a" ascii
    $s5  = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Professional\\VC\\Tools\\MSVC\\14.16.27023\\include\\xmemory0" fullword wide
    $s6  = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Professional\\VC\\Tools\\MSVC\\14.16.27023\\include\\vector" fullword wide
    $s7  = "std::_Tree_const_iterator<class std::_Tree_val<struct std::_Tree_simple_types<struct std::pair<class std::basic_string<char,stru" wide
    $s8  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ackage=\"Package_404_for_KB3125574~31bf385" ascii
    $s9  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s10 = "rn.=1uae\" WeNt 2_ N35\"dW/a> ~~4sW81k n 4bio3 .amo" fullword ascii
    $s11 = "Copyright (C) Microsoft Corp. 1992-2000" fullword wide
    $s12 = "\"1a6.  e55M1- _8e= ce ogee" fullword ascii
    $s13 = "std::vector<class nlohmann::basic_json<class std::map,class std::vector,class std::basic_string<char,struct std::char_traits<cha" wide
    $s14 = "std::_Tree_const_iterator<class std::_Tree_val<struct std::_Tree_simple_types<struct std::pair<class std::basic_string<char,stru" wide
    $s15 = "std::_Tree_const_iterator<class std::_Tree_val<struct std::_Tree_simple_types<struct std::pair<class std::basic_string<char,stru" wide
    $s16 = "std::_Tree_const_iterator<class std::_Tree_val<struct std::_Tree_simple_types<struct std::pair<class std::basic_string<char,stru" wide
    $s17 = "            <Install package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2313_neutral_LDR\"/>" fullword ascii
    $s18 = "            <Install package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2317_neutral_LDR\"/Pa~" ascii
    $s19 = "            <Install package=\"Package_404_for_KB3125574~31bf3856ad364e35~x86~~6.1.4.4\" update=\"3125574-2317_neutral_LDR\"/Pa~" ascii
    $s20 = "\"6e4e63\" 2 1B/.~1ev a rana oe4-\"  yxr 0giggtok3" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}