rule TTP_XOR_QUAD_CurrentVersionRun_b6db {
  strings:
    $key_b6db = { e5 b4 [2] c1 ba [2] ea 96 [2] c4 b4 [2] d0 af [2] df b5 [2] c1 a8 [2] c3 a9 [2] d8 af [2] c4 a8 [2] d8 87 }

  condition:
    any of them
}