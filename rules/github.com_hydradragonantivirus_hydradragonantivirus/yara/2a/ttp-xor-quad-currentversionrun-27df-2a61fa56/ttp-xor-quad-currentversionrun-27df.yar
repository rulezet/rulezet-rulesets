rule TTP_XOR_QUAD_CurrentVersionRun_27df {
  strings:
    $key_27df = { 74 b0 [2] 50 be [2] 7b 92 [2] 55 b0 [2] 41 ab [2] 4e b1 [2] 50 ac [2] 52 ad [2] 49 ab [2] 55 ac [2] 49 83 }

  condition:
    any of them
}