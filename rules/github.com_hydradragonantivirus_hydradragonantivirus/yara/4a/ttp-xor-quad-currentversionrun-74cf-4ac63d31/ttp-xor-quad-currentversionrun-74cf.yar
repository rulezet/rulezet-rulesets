rule TTP_XOR_QUAD_CurrentVersionRun_74cf {
  strings:
    $key_74cf = { 27 a0 [2] 03 ae [2] 28 82 [2] 06 a0 [2] 12 bb [2] 1d a1 [2] 03 bc [2] 01 bd [2] 1a bb [2] 06 bc [2] 1a 93 }

  condition:
    any of them
}