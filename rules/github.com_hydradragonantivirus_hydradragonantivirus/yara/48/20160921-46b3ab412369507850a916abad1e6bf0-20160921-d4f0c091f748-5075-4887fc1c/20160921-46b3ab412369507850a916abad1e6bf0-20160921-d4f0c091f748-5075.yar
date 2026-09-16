rule _20160921_46b3ab412369507850a916abad1e6bf0_20160921_d4f0c091f748_5075 {
  meta:
    description = "datamaliciousorder - from files 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "turn \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s2 = "tion f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s3 = "Ij\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4 = "\"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Yz\";})(),(functi" ascii
    $s5 = "ction f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}