rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_649e29a058d1_3676 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"

  strings:
    $s1 = "rn \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s2 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"" ascii
    $s3 = "eturn \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s4 = "nction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s5 = "(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s6 = "function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}