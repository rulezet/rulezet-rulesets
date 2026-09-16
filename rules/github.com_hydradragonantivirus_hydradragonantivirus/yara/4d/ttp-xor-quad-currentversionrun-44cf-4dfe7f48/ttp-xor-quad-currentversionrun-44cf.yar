rule TTP_XOR_QUAD_CurrentVersionRun_44cf {
  strings:
    $key_44cf = { 17 a0 [2] 33 ae [2] 18 82 [2] 36 a0 [2] 22 bb [2] 2d a1 [2] 33 bc [2] 31 bd [2] 2a bb [2] 36 bc [2] 2a 93 }

  condition:
    any of them
}