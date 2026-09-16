rule TTP_XOR_QUAD_CurrentVersionRun_cf86 {
  strings:
    $key_cf86 = { 9c e9 [2] b8 e7 [2] 93 cb [2] bd e9 [2] a9 f2 [2] a6 e8 [2] b8 f5 [2] ba f4 [2] a1 f2 [2] bd f5 [2] a1 da }

  condition:
    any of them
}