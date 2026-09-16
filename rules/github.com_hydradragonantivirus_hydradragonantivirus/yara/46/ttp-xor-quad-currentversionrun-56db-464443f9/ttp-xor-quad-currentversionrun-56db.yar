rule TTP_XOR_QUAD_CurrentVersionRun_56db {
  strings:
    $key_56db = { 05 b4 [2] 21 ba [2] 0a 96 [2] 24 b4 [2] 30 af [2] 3f b5 [2] 21 a8 [2] 23 a9 [2] 38 af [2] 24 a8 [2] 38 87 }

  condition:
    any of them
}