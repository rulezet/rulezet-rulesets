rule TTP_XOR_QUAD_CurrentVersionRun_4bcf {
  strings:
    $key_4bcf = { 18 a0 [2] 3c ae [2] 17 82 [2] 39 a0 [2] 2d bb [2] 22 a1 [2] 3c bc [2] 3e bd [2] 25 bb [2] 39 bc [2] 25 93 }

  condition:
    any of them
}