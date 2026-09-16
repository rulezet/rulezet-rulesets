rule TTP_XOR_QUAD_CurrentVersionRun_72db {
  strings:
    $key_72db = { 21 b4 [2] 05 ba [2] 2e 96 [2] 00 b4 [2] 14 af [2] 1b b5 [2] 05 a8 [2] 07 a9 [2] 1c af [2] 00 a8 [2] 1c 87 }

  condition:
    any of them
}