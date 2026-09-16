rule TTP_XOR_QUAD_CurrentVersionRun_7bcf {
  strings:
    $key_7bcf = { 28 a0 [2] 0c ae [2] 27 82 [2] 09 a0 [2] 1d bb [2] 12 a1 [2] 0c bc [2] 0e bd [2] 15 bb [2] 09 bc [2] 15 93 }

  condition:
    any of them
}