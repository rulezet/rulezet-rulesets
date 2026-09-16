rule _20160921_e98813a05e661b621a9d4b3a1d6d901f_20160921_ec2541ade561_2581 {
  meta:
    description = "datamaliciousorder - from files 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "n f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";" ascii
    $s3 = ",(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s4 = "nction f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){retur" ascii
    $s5 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s6 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000()" ascii
    $s7 = "n \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(fu" ascii
    $s8 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}