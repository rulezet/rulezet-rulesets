rule TTP_XOR_QUAD_CurrentVersionRun_c8ca {
  strings:
    $key_c8ca = { 9b a5 [2] bf ab [2] 94 87 [2] ba a5 [2] ae be [2] a1 a4 [2] bf b9 [2] bd b8 [2] a6 be [2] ba b9 [2] a6 96 }

  condition:
    any of them
}