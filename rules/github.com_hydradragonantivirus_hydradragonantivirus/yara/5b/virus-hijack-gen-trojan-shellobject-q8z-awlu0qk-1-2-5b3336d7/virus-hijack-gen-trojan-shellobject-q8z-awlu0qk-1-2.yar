rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4e5ba13cb40ce310326a033d6955916c4b6c10c4be65acf9f68fa344a7152bb"

  strings:
    $s1  = "property HomeAddressPostalCode" fullword ascii
    $s2  = "method GetFolderByIDWW" fullword ascii
    $s3  = "method GetPrev" fullword ascii
    $s4  = "method GetItemByID" fullword ascii
    $s5  = "method GetContacts" fullword ascii
    $s6  = "method GetFirstWWW" fullword ascii
    $s7  = "method GetContactFolderWWW" fullword ascii
    $s8  = "method GetFolderStructureW" fullword ascii
    $s9  = "method GetLast" fullword ascii
    $s10 = "property BusinessAddressPostalCode" fullword ascii
    $s11 = "property BusinessAddressStateW\"" fullword ascii
    $s12 = "property BusinessAddressStreet" fullword ascii
    $s13 = "property DefaultAddressWWW" fullword ascii
    $s14 = "property HomeAddressStateW" fullword ascii
    $s15 = "property HomeAddressCityWW" fullword ascii
    $s16 = "property Email1Address" fullword ascii
    $s17 = "property HomeAddressCountryWWW" fullword ascii
    $s18 = "property HomeAddressStreet" fullword ascii
    $s19 = "property BusinessAddressCityWW" fullword ascii
    $s20 = "property BusinessAddressCountryWWW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}