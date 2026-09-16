rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8ce19567f0dd09a7ba86646e6c6a9c1638e78e2146ae945c2495cf2a125bb1"

  strings:
    $x1  = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
    $s2  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/archive/iterators/base64_from_binary.hpp" fullword wide
    $s3  = "Query for operating system name failed." fullword ascii
    $s4  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/property_tree/json_parser/detail/parser.hpp" fullword ascii
    $s5  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/property_tree/string_path.hpp" fullword wide
    $s6  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/property_tree/detail/ptree_implementation.hpp" fullword ascii
    $s7  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\atlcomcli.h" fullword wide
    $s8  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/property_tree/json_parser/detail/narrow_encoding.hpp" fullword wide
    $s9  = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include\\boost/optional/optional.hpp" fullword wide
    $s10 = "Could not save to %s. Error Code: %d" fullword ascii
    $s11 = "strat disk check" fullword ascii
    $s12 = "connection error2" fullword ascii
    $s13 = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\atlexcept.h" fullword ascii
    $s14 = "connection error3" fullword ascii
    $s15 = "connection error4" fullword ascii
    $s16 = "connection error1" fullword ascii
    $s17 = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\cstringt.h" fullword wide
    $s18 = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\atlalloc.h" fullword wide
    $s19 = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\atlconv.h" fullword wide
    $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\atlmfc\\include\\atltransactionmanager.h" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}