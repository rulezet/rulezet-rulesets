rule TTP_XOR_QUAD_CurrentVersionRun_4dcf {
  strings:
    $key_4dcf = { 1e a0 [2] 3a ae [2] 11 82 [2] 3f a0 [2] 2b bb [2] 24 a1 [2] 3a bc [2] 38 bd [2] 23 bb [2] 3f bc [2] 23 93 }

  condition:
    any of them
}