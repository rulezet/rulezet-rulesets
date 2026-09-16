rule TTP_XOR_QUAD_CurrentVersionRun_3b80 {
  strings:
    $key_3b80 = { 68 ef [2] 4c e1 [2] 67 cd [2] 49 ef [2] 5d f4 [2] 52 ee [2] 4c f3 [2] 4e f2 [2] 55 f4 [2] 49 f3 [2] 55 dc }

  condition:
    any of them
}