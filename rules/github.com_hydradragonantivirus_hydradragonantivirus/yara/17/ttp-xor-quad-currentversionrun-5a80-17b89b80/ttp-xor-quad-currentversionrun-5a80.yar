rule TTP_XOR_QUAD_CurrentVersionRun_5a80 {
  strings:
    $key_5a80 = { 09 ef [2] 2d e1 [2] 06 cd [2] 28 ef [2] 3c f4 [2] 33 ee [2] 2d f3 [2] 2f f2 [2] 34 f4 [2] 28 f3 [2] 34 dc }

  condition:
    any of them
}