rule TTP_XOR_QUAD_CurrentVersionRun_30db {
  strings:
    $key_30db = { 63 b4 [2] 47 ba [2] 6c 96 [2] 42 b4 [2] 56 af [2] 59 b5 [2] 47 a8 [2] 45 a9 [2] 5e af [2] 42 a8 [2] 5e 87 }

  condition:
    any of them
}