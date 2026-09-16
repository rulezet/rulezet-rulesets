rule TTP_XOR_QUAD_CurrentVersionRun_a7b8 {
  strings:
    $key_a7b8 = { f4 d7 [2] d0 d9 [2] fb f5 [2] d5 d7 [2] c1 cc [2] ce d6 [2] d0 cb [2] d2 ca [2] c9 cc [2] d5 cb [2] c9 e4 }

  condition:
    any of them
}