rule TTP_XOR_QUAD_CurrentVersionRun_0780 {
  strings:
    $key_0780 = { 54 ef [2] 70 e1 [2] 5b cd [2] 75 ef [2] 61 f4 [2] 6e ee [2] 70 f3 [2] 72 f2 [2] 69 f4 [2] 75 f3 [2] 69 dc }

  condition:
    any of them
}