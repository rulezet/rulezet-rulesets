rule TTP_XOR_QUAD_CurrentVersionRun_f3df {
  strings:
    $key_f3df = { a0 b0 [2] 84 be [2] af 92 [2] 81 b0 [2] 95 ab [2] 9a b1 [2] 84 ac [2] 86 ad [2] 9d ab [2] 81 ac [2] 9d 83 }

  condition:
    any of them
}