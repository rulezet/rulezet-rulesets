rule TTP_XOR_QUAD_CurrentVersionRun_5ccf {
  strings:
    $key_5ccf = { 0f a0 [2] 2b ae [2] 00 82 [2] 2e a0 [2] 3a bb [2] 35 a1 [2] 2b bc [2] 29 bd [2] 32 bb [2] 2e bc [2] 32 93 }

  condition:
    any of them
}