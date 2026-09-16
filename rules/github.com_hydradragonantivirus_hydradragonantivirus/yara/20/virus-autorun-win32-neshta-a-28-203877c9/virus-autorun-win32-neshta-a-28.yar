rule Virus_Autorun_Win32_Neshta_A_28 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41e2820092c5ef15fe639086097d9a876a8b0f6b7dc2b3887fed8d83af9703cf"

  strings:
    $s1 = "Create Lights Providers in remote process" fullword ascii
    $s2 = "Remote Lights" fullword ascii
    $s3 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:368: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii
    $s4 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:146: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii
    $s5 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:223: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii
    $s6 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:223: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii
    $s7 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:368: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii
    $s8 = "..\\..\\third_party\\libc++\\src\\include\\__string\\char_traits.h:146: assertion !std::__is_pointer_in_range(__s1, __s1 + __n, " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}