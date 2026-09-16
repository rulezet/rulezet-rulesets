rule TTP_XOR_QUAD_CurrentVersionRun_56cf {
  strings:
    $key_56cf = { 05 a0 [2] 21 ae [2] 0a 82 [2] 24 a0 [2] 30 bb [2] 3f a1 [2] 21 bc [2] 23 bd [2] 38 bb [2] 24 bc [2] 38 93 }

  condition:
    any of them
}