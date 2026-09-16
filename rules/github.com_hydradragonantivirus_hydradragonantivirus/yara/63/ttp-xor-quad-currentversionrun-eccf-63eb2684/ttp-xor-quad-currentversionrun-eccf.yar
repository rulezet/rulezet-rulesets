rule TTP_XOR_QUAD_CurrentVersionRun_eccf {
  strings:
    $key_eccf = { bf a0 [2] 9b ae [2] b0 82 [2] 9e a0 [2] 8a bb [2] 85 a1 [2] 9b bc [2] 99 bd [2] 82 bb [2] 9e bc [2] 82 93 }

  condition:
    any of them
}