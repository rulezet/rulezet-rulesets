rule TTP_XOR_QUAD_CurrentVersionRun_4e80 {
  strings:
    $key_4e80 = { 1d ef [2] 39 e1 [2] 12 cd [2] 3c ef [2] 28 f4 [2] 27 ee [2] 39 f3 [2] 3b f2 [2] 20 f4 [2] 3c f3 [2] 20 dc }

  condition:
    any of them
}