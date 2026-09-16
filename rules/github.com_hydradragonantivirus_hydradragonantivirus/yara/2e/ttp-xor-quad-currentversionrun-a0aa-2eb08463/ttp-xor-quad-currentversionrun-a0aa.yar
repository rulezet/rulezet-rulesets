rule TTP_XOR_QUAD_CurrentVersionRun_a0aa {
  strings:
    $key_a0aa = { f3 c5 [2] d7 cb [2] fc e7 [2] d2 c5 [2] c6 de [2] c9 c4 [2] d7 d9 [2] d5 d8 [2] ce de [2] d2 d9 [2] ce f6 }

  condition:
    any of them
}