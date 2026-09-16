rule TTP_XOR_QUAD_CurrentVersionRun_a4db {
  strings:
    $key_a4db = { f7 b4 [2] d3 ba [2] f8 96 [2] d6 b4 [2] c2 af [2] cd b5 [2] d3 a8 [2] d1 a9 [2] ca af [2] d6 a8 [2] ca 87 }

  condition:
    any of them
}