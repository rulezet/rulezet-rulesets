rule TTP_XOR_QUAD_CurrentVersionRun_3780 {
  strings:
    $key_3780 = { 64 ef [2] 40 e1 [2] 6b cd [2] 45 ef [2] 51 f4 [2] 5e ee [2] 40 f3 [2] 42 f2 [2] 59 f4 [2] 45 f3 [2] 59 dc }

  condition:
    any of them
}