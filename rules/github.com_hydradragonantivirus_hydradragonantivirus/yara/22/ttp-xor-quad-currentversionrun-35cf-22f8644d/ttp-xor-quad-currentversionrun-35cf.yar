rule TTP_XOR_QUAD_CurrentVersionRun_35cf {
  strings:
    $key_35cf = { 66 a0 [2] 42 ae [2] 69 82 [2] 47 a0 [2] 53 bb [2] 5c a1 [2] 42 bc [2] 40 bd [2] 5b bb [2] 47 bc [2] 5b 93 }

  condition:
    any of them
}