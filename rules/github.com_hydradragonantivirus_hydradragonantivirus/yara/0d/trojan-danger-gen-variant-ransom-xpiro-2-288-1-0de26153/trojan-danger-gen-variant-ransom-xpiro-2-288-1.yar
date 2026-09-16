rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_288_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_288_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55720a9822897cff87effbc9ca9c27138bc88c3d18273498a97d4fc2bbc4d91c"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "image::write_file(str _0, Tensor _1) -> " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}