rule TTP_XOR_QUAD_CurrentVersionRun_40db {
  strings:
    $key_40db = { 13 b4 [2] 37 ba [2] 1c 96 [2] 32 b4 [2] 26 af [2] 29 b5 [2] 37 a8 [2] 35 a9 [2] 2e af [2] 32 a8 [2] 2e 87 }

  condition:
    any of them
}