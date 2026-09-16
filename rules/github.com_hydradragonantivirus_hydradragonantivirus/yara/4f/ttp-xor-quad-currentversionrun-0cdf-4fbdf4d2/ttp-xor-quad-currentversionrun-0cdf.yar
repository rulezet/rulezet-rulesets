rule TTP_XOR_QUAD_CurrentVersionRun_0cdf {
  strings:
    $key_0cdf = { 5f b0 [2] 7b be [2] 50 92 [2] 7e b0 [2] 6a ab [2] 65 b1 [2] 7b ac [2] 79 ad [2] 62 ab [2] 7e ac [2] 62 83 }

  condition:
    any of them
}