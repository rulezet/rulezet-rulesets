rule TTP_XOR_QUAD_CurrentVersionRun_ce81 {
  strings:
    $key_ce81 = { 9d ee [2] b9 e0 [2] 92 cc [2] bc ee [2] a8 f5 [2] a7 ef [2] b9 f2 [2] bb f3 [2] a0 f5 [2] bc f2 [2] a0 dd }

  condition:
    any of them
}