rule TTP_XOR_QUAD_CurrentVersionRun_4ccf {
  strings:
    $key_4ccf = { 1f a0 [2] 3b ae [2] 10 82 [2] 3e a0 [2] 2a bb [2] 25 a1 [2] 3b bc [2] 39 bd [2] 22 bb [2] 3e bc [2] 22 93 }

  condition:
    any of them
}