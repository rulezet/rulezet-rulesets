rule TTP_XOR_QUAD_CurrentVersionRun_6a80 {
  strings:
    $key_6a80 = { 39 ef [2] 1d e1 [2] 36 cd [2] 18 ef [2] 0c f4 [2] 03 ee [2] 1d f3 [2] 1f f2 [2] 04 f4 [2] 18 f3 [2] 04 dc }

  condition:
    any of them
}