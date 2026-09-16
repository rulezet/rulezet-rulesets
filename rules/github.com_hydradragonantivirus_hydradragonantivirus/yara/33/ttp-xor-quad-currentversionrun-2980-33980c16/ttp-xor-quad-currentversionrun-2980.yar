rule TTP_XOR_QUAD_CurrentVersionRun_2980 {
  strings:
    $key_2980 = { 7a ef [2] 5e e1 [2] 75 cd [2] 5b ef [2] 4f f4 [2] 40 ee [2] 5e f3 [2] 5c f2 [2] 47 f4 [2] 5b f3 [2] 47 dc }

  condition:
    any of them
}