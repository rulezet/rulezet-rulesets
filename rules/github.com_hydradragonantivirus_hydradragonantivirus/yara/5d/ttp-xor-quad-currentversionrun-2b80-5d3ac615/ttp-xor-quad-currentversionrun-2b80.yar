rule TTP_XOR_QUAD_CurrentVersionRun_2b80 {
  strings:
    $key_2b80 = { 78 ef [2] 5c e1 [2] 77 cd [2] 59 ef [2] 4d f4 [2] 42 ee [2] 5c f3 [2] 5e f2 [2] 45 f4 [2] 59 f3 [2] 45 dc }

  condition:
    any of them
}