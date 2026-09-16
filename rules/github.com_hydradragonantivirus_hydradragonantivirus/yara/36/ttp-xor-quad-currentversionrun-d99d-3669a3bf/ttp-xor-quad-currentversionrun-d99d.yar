rule TTP_XOR_QUAD_CurrentVersionRun_d99d {
  strings:
    $key_d99d = { 8a f2 [2] ae fc [2] 85 d0 [2] ab f2 [2] bf e9 [2] b0 f3 [2] ae ee [2] ac ef [2] b7 e9 [2] ab ee [2] b7 c1 }

  condition:
    any of them
}