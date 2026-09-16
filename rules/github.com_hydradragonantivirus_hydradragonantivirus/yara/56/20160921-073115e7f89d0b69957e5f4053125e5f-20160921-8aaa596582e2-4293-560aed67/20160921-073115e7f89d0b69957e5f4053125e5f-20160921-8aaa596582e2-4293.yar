rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_8aaa596582e2_4293 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash3       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash4       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash5       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "nction f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s2 = "return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s3 = "\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s4 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s5 = "\"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}