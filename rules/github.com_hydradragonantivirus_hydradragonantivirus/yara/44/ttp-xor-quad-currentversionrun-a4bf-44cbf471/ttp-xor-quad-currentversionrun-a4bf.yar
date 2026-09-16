rule TTP_XOR_QUAD_CurrentVersionRun_a4bf {
  strings:
    $key_a4bf = { f7 d0 [2] d3 de [2] f8 f2 [2] d6 d0 [2] c2 cb [2] cd d1 [2] d3 cc [2] d1 cd [2] ca cb [2] d6 cc [2] ca e3 }

  condition:
    any of them
}