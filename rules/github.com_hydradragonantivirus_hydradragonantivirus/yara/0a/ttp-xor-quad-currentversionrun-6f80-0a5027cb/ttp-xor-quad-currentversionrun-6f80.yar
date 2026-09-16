rule TTP_XOR_QUAD_CurrentVersionRun_6f80 {
  strings:
    $key_6f80 = { 3c ef [2] 18 e1 [2] 33 cd [2] 1d ef [2] 09 f4 [2] 06 ee [2] 18 f3 [2] 1a f2 [2] 01 f4 [2] 1d f3 [2] 01 dc }

  condition:
    any of them
}