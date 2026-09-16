rule TTP_XOR_QUAD_CurrentVersionRun_da9c {
  strings:
    $key_da9c = { 89 f3 [2] ad fd [2] 86 d1 [2] a8 f3 [2] bc e8 [2] b3 f2 [2] ad ef [2] af ee [2] b4 e8 [2] a8 ef [2] b4 c0 }

  condition:
    any of them
}