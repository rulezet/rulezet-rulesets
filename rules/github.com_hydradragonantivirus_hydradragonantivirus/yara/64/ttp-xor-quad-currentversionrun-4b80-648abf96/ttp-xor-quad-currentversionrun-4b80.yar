rule TTP_XOR_QUAD_CurrentVersionRun_4b80 {
  strings:
    $key_4b80 = { 18 ef [2] 3c e1 [2] 17 cd [2] 39 ef [2] 2d f4 [2] 22 ee [2] 3c f3 [2] 3e f2 [2] 25 f4 [2] 39 f3 [2] 25 dc }

  condition:
    any of them
}