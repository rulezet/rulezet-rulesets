rule TTP_XOR_QUAD_CurrentVersionRun_ebcf {
  strings:
    $key_ebcf = { b8 a0 [2] 9c ae [2] b7 82 [2] 99 a0 [2] 8d bb [2] 82 a1 [2] 9c bc [2] 9e bd [2] 85 bb [2] 99 bc [2] 85 93 }

  condition:
    any of them
}