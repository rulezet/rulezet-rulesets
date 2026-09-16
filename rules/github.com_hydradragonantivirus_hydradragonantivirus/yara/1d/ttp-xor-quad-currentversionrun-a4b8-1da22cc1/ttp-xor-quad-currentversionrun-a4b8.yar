rule TTP_XOR_QUAD_CurrentVersionRun_a4b8 {
  strings:
    $key_a4b8 = { f7 d7 [2] d3 d9 [2] f8 f5 [2] d6 d7 [2] c2 cc [2] cd d6 [2] d3 cb [2] d1 ca [2] ca cc [2] d6 cb [2] ca e4 }

  condition:
    any of them
}