rule TTP_XOR_QUAD_CurrentVersionRun_2780 {
  strings:
    $key_2780 = { 74 ef [2] 50 e1 [2] 7b cd [2] 55 ef [2] 41 f4 [2] 4e ee [2] 50 f3 [2] 52 f2 [2] 49 f4 [2] 55 f3 [2] 49 dc }

  condition:
    any of them
}