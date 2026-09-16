rule TTP_XOR_QUAD_CurrentVersionRun_eddf {
  strings:
    $key_eddf = { be b0 [2] 9a be [2] b1 92 [2] 9f b0 [2] 8b ab [2] 84 b1 [2] 9a ac [2] 98 ad [2] 83 ab [2] 9f ac [2] 83 83 }

  condition:
    any of them
}