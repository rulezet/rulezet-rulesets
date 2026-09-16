rule TTP_XOR_QUAD_CurrentVersionRun_36cf {
  strings:
    $key_36cf = { 65 a0 [2] 41 ae [2] 6a 82 [2] 44 a0 [2] 50 bb [2] 5f a1 [2] 41 bc [2] 43 bd [2] 58 bb [2] 44 bc [2] 58 93 }

  condition:
    any of them
}