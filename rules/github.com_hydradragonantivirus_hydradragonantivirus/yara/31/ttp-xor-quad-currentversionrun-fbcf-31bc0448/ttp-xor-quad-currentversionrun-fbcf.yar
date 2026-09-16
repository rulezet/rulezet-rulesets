rule TTP_XOR_QUAD_CurrentVersionRun_fbcf {
  strings:
    $key_fbcf = { a8 a0 [2] 8c ae [2] a7 82 [2] 89 a0 [2] 9d bb [2] 92 a1 [2] 8c bc [2] 8e bd [2] 95 bb [2] 89 bc [2] 95 93 }

  condition:
    any of them
}