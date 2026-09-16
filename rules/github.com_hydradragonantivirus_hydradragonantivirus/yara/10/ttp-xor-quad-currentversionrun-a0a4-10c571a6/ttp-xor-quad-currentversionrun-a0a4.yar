rule TTP_XOR_QUAD_CurrentVersionRun_a0a4 {
  strings:
    $key_a0a4 = { f3 cb [2] d7 c5 [2] fc e9 [2] d2 cb [2] c6 d0 [2] c9 ca [2] d7 d7 [2] d5 d6 [2] ce d0 [2] d2 d7 [2] ce f8 }

  condition:
    any of them
}