rule TTP_XOR_QUAD_CurrentVersionRun_f2df {
  strings:
    $key_f2df = { a1 b0 [2] 85 be [2] ae 92 [2] 80 b0 [2] 94 ab [2] 9b b1 [2] 85 ac [2] 87 ad [2] 9c ab [2] 80 ac [2] 9c 83 }

  condition:
    any of them
}