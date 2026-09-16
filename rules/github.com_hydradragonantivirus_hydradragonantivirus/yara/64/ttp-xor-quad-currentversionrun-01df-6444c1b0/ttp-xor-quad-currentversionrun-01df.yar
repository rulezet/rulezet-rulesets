rule TTP_XOR_QUAD_CurrentVersionRun_01df {
  strings:
    $key_01df = { 52 b0 [2] 76 be [2] 5d 92 [2] 73 b0 [2] 67 ab [2] 68 b1 [2] 76 ac [2] 74 ad [2] 6f ab [2] 73 ac [2] 6f 83 }

  condition:
    any of them
}