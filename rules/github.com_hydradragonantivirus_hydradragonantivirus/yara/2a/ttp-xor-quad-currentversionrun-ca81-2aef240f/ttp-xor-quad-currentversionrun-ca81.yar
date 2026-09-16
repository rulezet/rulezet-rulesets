rule TTP_XOR_QUAD_CurrentVersionRun_ca81 {
  strings:
    $key_ca81 = { 99 ee [2] bd e0 [2] 96 cc [2] b8 ee [2] ac f5 [2] a3 ef [2] bd f2 [2] bf f3 [2] a4 f5 [2] b8 f2 [2] a4 dd }

  condition:
    any of them
}