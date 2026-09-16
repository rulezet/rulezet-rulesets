rule TTP_XOR_QUAD_CurrentVersionRun_a7db {
  strings:
    $key_a7db = { f4 b4 [2] d0 ba [2] fb 96 [2] d5 b4 [2] c1 af [2] ce b5 [2] d0 a8 [2] d2 a9 [2] c9 af [2] d5 a8 [2] c9 87 }

  condition:
    any of them
}