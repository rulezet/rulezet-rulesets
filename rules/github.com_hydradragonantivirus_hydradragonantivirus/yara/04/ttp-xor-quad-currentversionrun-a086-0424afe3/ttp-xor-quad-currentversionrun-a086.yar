rule TTP_XOR_QUAD_CurrentVersionRun_a086 {
  strings:
    $key_a086 = { f3 e9 [2] d7 e7 [2] fc cb [2] d2 e9 [2] c6 f2 [2] c9 e8 [2] d7 f5 [2] d5 f4 [2] ce f2 [2] d2 f5 [2] ce da }

  condition:
    any of them
}