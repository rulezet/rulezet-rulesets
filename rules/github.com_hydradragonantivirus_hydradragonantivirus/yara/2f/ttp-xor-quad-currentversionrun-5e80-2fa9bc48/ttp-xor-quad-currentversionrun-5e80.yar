rule TTP_XOR_QUAD_CurrentVersionRun_5e80 {
  strings:
    $key_5e80 = { 0d ef [2] 29 e1 [2] 02 cd [2] 2c ef [2] 38 f4 [2] 37 ee [2] 29 f3 [2] 2b f2 [2] 30 f4 [2] 2c f3 [2] 30 dc }

  condition:
    any of them
}