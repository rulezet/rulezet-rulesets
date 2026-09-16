rule TTP_XOR_QUAD_CurrentVersionRun_c1df {
  strings:
    $key_c1df = { 92 b0 [2] b6 be [2] 9d 92 [2] b3 b0 [2] a7 ab [2] a8 b1 [2] b6 ac [2] b4 ad [2] af ab [2] b3 ac [2] af 83 }

  condition:
    any of them
}