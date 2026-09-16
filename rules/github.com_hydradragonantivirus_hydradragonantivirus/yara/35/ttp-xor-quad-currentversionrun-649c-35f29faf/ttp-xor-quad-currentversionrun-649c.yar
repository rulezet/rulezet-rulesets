rule TTP_XOR_QUAD_CurrentVersionRun_649c {
  strings:
    $key_649c = { 37 f3 [2] 13 fd [2] 38 d1 [2] 16 f3 [2] 02 e8 [2] 0d f2 [2] 13 ef [2] 11 ee [2] 0a e8 [2] 16 ef [2] 0a c0 }

  condition:
    any of them
}