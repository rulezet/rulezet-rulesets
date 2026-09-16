rule TTP_XOR_QUAD_CurrentVersionRun_9cdf {
  strings:
    $key_9cdf = { cf b0 [2] eb be [2] c0 92 [2] ee b0 [2] fa ab [2] f5 b1 [2] eb ac [2] e9 ad [2] f2 ab [2] ee ac [2] f2 83 }

  condition:
    any of them
}