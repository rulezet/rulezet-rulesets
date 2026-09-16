import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_283_1_Virus_Hijack_Trojan_116 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_283_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_284_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_285_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c845b259264a23fa465cb59c422fd851c95dd92b5d26d2cec867085623e18df"
    hash2       = "3044e01a1877af43c81c2585f2dc9842d9c9a562da13e215e5197a0142eb825f"
    hash3       = "75f14fff0b30ca2658fa6824459ebc5d9ff31463bb44e33856d1e33d3db24c53"

  strings:
    $s1  = "??_C@_07EMGJIMLB@execute?$AA@" fullword ascii
    $s2  = "important files" fullword ascii
    $s3  = "my account" fullword ascii
    $s4  = "??_C@_0BA@DAHKIDJI@important?5files?$AA@" fullword ascii
    $s5  = "std.basic_ifstream<char,std::char_traits<char> >.rdbuf" fullword ascii
    $s6  = "??_C@_06JIODDOFH@System?$AA@" fullword ascii
    $s7  = "??_C@_05NAOIJFC@Error?$AA@" fullword ascii
    $s8  = "??_C@_09MCGAFAPH@Important?$AA@" fullword ascii
    $s9  = "std.basic_ifstream<char,std::char_traits<char> >.close" fullword ascii
    $s10 = "stdext.unchecked_uninitialized_copy<class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_" ascii
    $s11 = "std.basic_ostream<char,std::char_traits<char> >.seekp" fullword ascii
    $s12 = "more files" fullword ascii
    $s13 = "??_C@_0L@NHEGCEPP@more?5files?$AA@" fullword ascii
    $s14 = "t> > * *,class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> > * *,class std::allocat" ascii
    $s15 = "traits<char> > >" fullword ascii
    $s16 = "har_traits<char> > >" fullword ascii
    $s17 = "??_C@_04MDPPAFID@disk?$AA@" fullword ascii
    $s18 = "view \\\\" fullword wide
    $s19 = "std.vector<char *,std::allocator<char *> >.{dtor}" fullword ascii
    $s20 = "std.basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t> >._Construct<class std::_String_iterator<char,struct " ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cab483e20539116bcfe57051284bc34b" and (8 of them)
    ) or (all of them)
}