rule TTP_XOR_QUAD_CurrentVersionRun_eb80 {
  strings:
    $key_eb80 = { b8 ef [2] 9c e1 [2] b7 cd [2] 99 ef [2] 8d f4 [2] 82 ee [2] 9c f3 [2] 9e f2 [2] 85 f4 [2] 99 f3 [2] 85 dc }

  condition:
    any of them
}