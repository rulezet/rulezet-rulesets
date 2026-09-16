rule sig_20160517_1c4e6737faf81f7fbad1bb8cbef59801 {
  meta:
    description = "datamaliciousorder - file 20160517_1c4e6737faf81f7fbad1bb8cbef59801.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "132664c1c30d7925c0cc85f53dad222a159a155338b9528dd9cbcb4cfc2d5aa7"

  strings:
    $s1 = "var sxl='vpbmapasy4nxrifumo jfeovgvxvll4ohqnvrrm14qzoqptesfloh2qfrhlfrtvd3gbpwrij=sz1o3\\'betg3tqxnqeciwz1hnpcdmfiqfbfrfvxrpluxg" ascii
    $s2 = "ks2;pyoid z3uhlhow1qfckbrg4tjzx2h cl2udclccroaffrdq{xcndx)fu3oarnzaa2 vknmf(dpl2gejkqvs;w2yye gv4zk nbjif}dxu4k my4oz}fskanfylpb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}