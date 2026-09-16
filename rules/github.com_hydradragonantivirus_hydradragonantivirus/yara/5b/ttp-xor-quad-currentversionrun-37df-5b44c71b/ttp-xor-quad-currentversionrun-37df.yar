rule TTP_XOR_QUAD_CurrentVersionRun_37df {
  strings:
    $key_37df = { 64 b0 [2] 40 be [2] 6b 92 [2] 45 b0 [2] 51 ab [2] 5e b1 [2] 40 ac [2] 42 ad [2] 59 ab [2] 45 ac [2] 59 83 }

  condition:
    any of them
}