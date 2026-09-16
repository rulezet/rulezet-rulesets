rule TTP_XOR_QUAD_CurrentVersionRun_2ccf {
  strings:
    $key_2ccf = { 7f a0 [2] 5b ae [2] 70 82 [2] 5e a0 [2] 4a bb [2] 45 a1 [2] 5b bc [2] 59 bd [2] 42 bb [2] 5e bc [2] 42 93 }

  condition:
    any of them
}