rule TTP_XOR_QUAD_CurrentVersionRun_41db {
  strings:
    $key_41db = { 12 b4 [2] 36 ba [2] 1d 96 [2] 33 b4 [2] 27 af [2] 28 b5 [2] 36 a8 [2] 34 a9 [2] 2f af [2] 33 a8 [2] 2f 87 }

  condition:
    any of them
}