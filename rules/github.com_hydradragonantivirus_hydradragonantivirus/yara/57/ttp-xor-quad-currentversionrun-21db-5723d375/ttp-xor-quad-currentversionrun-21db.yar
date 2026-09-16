rule TTP_XOR_QUAD_CurrentVersionRun_21db {
  strings:
    $key_21db = { 72 b4 [2] 56 ba [2] 7d 96 [2] 53 b4 [2] 47 af [2] 48 b5 [2] 56 a8 [2] 54 a9 [2] 4f af [2] 53 a8 [2] 4f 87 }

  condition:
    any of them
}