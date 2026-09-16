rule TTP_XOR_QUAD_CurrentVersionRun_7980 {
  strings:
    $key_7980 = { 2a ef [2] 0e e1 [2] 25 cd [2] 0b ef [2] 1f f4 [2] 10 ee [2] 0e f3 [2] 0c f2 [2] 17 f4 [2] 0b f3 [2] 17 dc }

  condition:
    any of them
}