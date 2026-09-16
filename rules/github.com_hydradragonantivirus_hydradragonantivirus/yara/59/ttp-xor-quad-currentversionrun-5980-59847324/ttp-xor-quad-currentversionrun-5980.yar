rule TTP_XOR_QUAD_CurrentVersionRun_5980 {
  strings:
    $key_5980 = { 0a ef [2] 2e e1 [2] 05 cd [2] 2b ef [2] 3f f4 [2] 30 ee [2] 2e f3 [2] 2c f2 [2] 37 f4 [2] 2b f3 [2] 37 dc }

  condition:
    any of them
}