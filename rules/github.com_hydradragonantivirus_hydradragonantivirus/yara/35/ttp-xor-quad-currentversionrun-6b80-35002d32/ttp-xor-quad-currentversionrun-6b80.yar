rule TTP_XOR_QUAD_CurrentVersionRun_6b80 {
  strings:
    $key_6b80 = { 38 ef [2] 1c e1 [2] 37 cd [2] 19 ef [2] 0d f4 [2] 02 ee [2] 1c f3 [2] 1e f2 [2] 05 f4 [2] 19 f3 [2] 05 dc }

  condition:
    any of them
}