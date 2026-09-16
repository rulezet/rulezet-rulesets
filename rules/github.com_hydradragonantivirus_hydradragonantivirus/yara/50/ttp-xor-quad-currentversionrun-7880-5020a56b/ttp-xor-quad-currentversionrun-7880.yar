rule TTP_XOR_QUAD_CurrentVersionRun_7880 {
  strings:
    $key_7880 = { 2b ef [2] 0f e1 [2] 24 cd [2] 0a ef [2] 1e f4 [2] 11 ee [2] 0f f3 [2] 0d f2 [2] 16 f4 [2] 0a f3 [2] 16 dc }

  condition:
    any of them
}