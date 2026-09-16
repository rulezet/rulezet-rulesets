rule TTP_XOR_QUAD_CurrentVersionRun_76cf {
  strings:
    $key_76cf = { 25 a0 [2] 01 ae [2] 2a 82 [2] 04 a0 [2] 10 bb [2] 1f a1 [2] 01 bc [2] 03 bd [2] 18 bb [2] 04 bc [2] 18 93 }

  condition:
    any of them
}