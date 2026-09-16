rule TTP_XOR_QUAD_CurrentVersionRun_e3df {
  strings:
    $key_e3df = { b0 b0 [2] 94 be [2] bf 92 [2] 91 b0 [2] 85 ab [2] 8a b1 [2] 94 ac [2] 96 ad [2] 8d ab [2] 91 ac [2] 8d 83 }

  condition:
    any of them
}