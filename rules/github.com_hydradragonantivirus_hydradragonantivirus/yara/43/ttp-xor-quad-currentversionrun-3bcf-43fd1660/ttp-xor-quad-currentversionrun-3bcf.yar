rule TTP_XOR_QUAD_CurrentVersionRun_3bcf {
  strings:
    $key_3bcf = { 68 a0 [2] 4c ae [2] 67 82 [2] 49 a0 [2] 5d bb [2] 52 a1 [2] 4c bc [2] 4e bd [2] 55 bb [2] 49 bc [2] 55 93 }

  condition:
    any of them
}