rule TTP_XOR_QUAD_CurrentVersionRun_0e80 {
  strings:
    $key_0e80 = { 5d ef [2] 79 e1 [2] 52 cd [2] 7c ef [2] 68 f4 [2] 67 ee [2] 79 f3 [2] 7b f2 [2] 60 f4 [2] 7c f3 [2] 60 dc }

  condition:
    any of them
}