rule TTP_XOR_QUAD_CurrentVersionRun_2cdf {
  strings:
    $key_2cdf = { 7f b0 [2] 5b be [2] 70 92 [2] 5e b0 [2] 4a ab [2] 45 b1 [2] 5b ac [2] 59 ad [2] 42 ab [2] 5e ac [2] 42 83 }

  condition:
    any of them
}