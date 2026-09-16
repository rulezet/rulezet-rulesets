rule TTP_XOR_QUAD_CurrentVersionRun_cd65 {
  strings:
    $key_cd65 = { 9e 0a [2] ba 04 [2] 91 28 [2] bf 0a [2] ab 11 [2] a4 0b [2] ba 16 [2] b8 17 [2] a3 11 [2] bf 16 [2] a3 39 }

  condition:
    any of them
}