rule TTP_XOR_QUAD_CurrentVersionRun_c5df {
  strings:
    $key_c5df = { 96 b0 [2] b2 be [2] 99 92 [2] b7 b0 [2] a3 ab [2] ac b1 [2] b2 ac [2] b0 ad [2] ab ab [2] b7 ac [2] ab 83 }

  condition:
    any of them
}