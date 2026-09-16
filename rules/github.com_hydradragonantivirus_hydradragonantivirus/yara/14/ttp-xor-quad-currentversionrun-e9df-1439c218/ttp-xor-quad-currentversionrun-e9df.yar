rule TTP_XOR_QUAD_CurrentVersionRun_e9df {
  strings:
    $key_e9df = { ba b0 [2] 9e be [2] b5 92 [2] 9b b0 [2] 8f ab [2] 80 b1 [2] 9e ac [2] 9c ad [2] 87 ab [2] 9b ac [2] 87 83 }

  condition:
    any of them
}