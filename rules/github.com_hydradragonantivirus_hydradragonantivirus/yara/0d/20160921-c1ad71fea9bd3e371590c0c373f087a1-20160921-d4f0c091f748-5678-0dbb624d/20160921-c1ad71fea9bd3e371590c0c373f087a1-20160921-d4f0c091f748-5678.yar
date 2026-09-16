rule _20160921_c1ad71fea9bd3e371590c0c373f087a1_20160921_d4f0c091f748_5678 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "\"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(functi" ascii
    $s2 = "(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3 = "){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";}" ascii
    $s4 = "tion f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s5 = "),(function f000(){return \"Br\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}