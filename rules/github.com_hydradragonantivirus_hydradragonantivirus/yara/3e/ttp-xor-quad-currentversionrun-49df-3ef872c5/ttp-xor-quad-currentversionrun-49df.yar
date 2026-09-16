rule TTP_XOR_QUAD_CurrentVersionRun_49df {
  strings:
    $key_49df = { 1a b0 [2] 3e be [2] 15 92 [2] 3b b0 [2] 2f ab [2] 20 b1 [2] 3e ac [2] 3c ad [2] 27 ab [2] 3b ac [2] 27 83 }

  condition:
    any of them
}