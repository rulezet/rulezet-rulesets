rule TTP_XOR_QUAD_CurrentVersionRun_1ddf {
  strings:
    $key_1ddf = { 4e b0 [2] 6a be [2] 41 92 [2] 6f b0 [2] 7b ab [2] 74 b1 [2] 6a ac [2] 68 ad [2] 73 ab [2] 6f ac [2] 73 83 }

  condition:
    any of them
}