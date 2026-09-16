rule TTP_XOR_QUAD_CurrentVersionRun_61df {
  strings:
    $key_61df = { 32 b0 [2] 16 be [2] 3d 92 [2] 13 b0 [2] 07 ab [2] 08 b1 [2] 16 ac [2] 14 ad [2] 0f ab [2] 13 ac [2] 0f 83 }

  condition:
    any of them
}