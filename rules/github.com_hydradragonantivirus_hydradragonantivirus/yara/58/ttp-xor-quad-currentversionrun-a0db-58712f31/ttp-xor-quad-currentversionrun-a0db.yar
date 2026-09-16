rule TTP_XOR_QUAD_CurrentVersionRun_a0db {
  strings:
    $key_a0db = { f3 b4 [2] d7 ba [2] fc 96 [2] d2 b4 [2] c6 af [2] c9 b5 [2] d7 a8 [2] d5 a9 [2] ce af [2] d2 a8 [2] ce 87 }

  condition:
    any of them
}