rule TTP_XOR_QUAD_CurrentVersionRun_48df {
  strings:
    $key_48df = { 1b b0 [2] 3f be [2] 14 92 [2] 3a b0 [2] 2e ab [2] 21 b1 [2] 3f ac [2] 3d ad [2] 26 ab [2] 3a ac [2] 26 83 }

  condition:
    any of them
}