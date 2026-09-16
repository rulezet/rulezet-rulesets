rule TTP_XOR_QUAD_CurrentVersionRun_0bcf {
  strings:
    $key_0bcf = { 58 a0 [2] 7c ae [2] 57 82 [2] 79 a0 [2] 6d bb [2] 62 a1 [2] 7c bc [2] 7e bd [2] 65 bb [2] 79 bc [2] 65 93 }

  condition:
    any of them
}