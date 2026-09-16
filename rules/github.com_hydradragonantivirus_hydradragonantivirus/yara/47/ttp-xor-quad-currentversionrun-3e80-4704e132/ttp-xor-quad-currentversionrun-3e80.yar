rule TTP_XOR_QUAD_CurrentVersionRun_3e80 {
  strings:
    $key_3e80 = { 6d ef [2] 49 e1 [2] 62 cd [2] 4c ef [2] 58 f4 [2] 57 ee [2] 49 f3 [2] 4b f2 [2] 50 f4 [2] 4c f3 [2] 50 dc }

  condition:
    any of them
}