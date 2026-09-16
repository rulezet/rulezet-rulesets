rule TTP_XOR_QUAD_CurrentVersionRun_4dcb {
  strings:
    $key_4dcb = { 1e a4 [2] 3a aa [2] 11 86 [2] 3f a4 [2] 2b bf [2] 24 a5 [2] 3a b8 [2] 38 b9 [2] 23 bf [2] 3f b8 [2] 23 97 }

  condition:
    any of them
}