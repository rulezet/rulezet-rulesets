rule TTP_XOR_QUAD_CurrentVersionRun_1dcb {
  strings:
    $key_1dcb = { 4e a4 [2] 6a aa [2] 41 86 [2] 6f a4 [2] 7b bf [2] 74 a5 [2] 6a b8 [2] 68 b9 [2] 73 bf [2] 6f b8 [2] 73 97 }

  condition:
    any of them
}