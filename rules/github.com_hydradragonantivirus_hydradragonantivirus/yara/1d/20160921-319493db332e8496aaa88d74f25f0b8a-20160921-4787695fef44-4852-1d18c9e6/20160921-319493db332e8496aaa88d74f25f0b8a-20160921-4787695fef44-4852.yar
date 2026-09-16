rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_4787695fef44_4852 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"

  strings:
    $s1 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f0" ascii
    $s2 = "){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f00" ascii
    $s4 = "n \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s5 = "tion f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}