rule TTP_XOR_QUAD_CurrentVersionRun_3ccf {
  strings:
    $key_3ccf = { 6f a0 [2] 4b ae [2] 60 82 [2] 4e a0 [2] 5a bb [2] 55 a1 [2] 4b bc [2] 49 bd [2] 52 bb [2] 4e bc [2] 52 93 }

  condition:
    any of them
}