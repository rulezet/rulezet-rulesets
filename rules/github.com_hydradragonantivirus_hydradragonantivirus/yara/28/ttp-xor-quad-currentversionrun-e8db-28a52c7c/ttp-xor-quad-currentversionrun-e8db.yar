rule TTP_XOR_QUAD_CurrentVersionRun_e8db {
  strings:
    $key_e8db = { bb b4 [2] 9f ba [2] b4 96 [2] 9a b4 [2] 8e af [2] 81 b5 [2] 9f a8 [2] 9d a9 [2] 86 af [2] 9a a8 [2] 86 87 }

  condition:
    any of them
}