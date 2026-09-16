rule TTP_XOR_QUAD_CurrentVersionRun_d381 {
  strings:
    $key_d381 = { 80 ee [2] a4 e0 [2] 8f cc [2] a1 ee [2] b5 f5 [2] ba ef [2] a4 f2 [2] a6 f3 [2] bd f5 [2] a1 f2 [2] bd dd }

  condition:
    any of them
}