rule TTP_XOR_QUAD_CurrentVersionRun_2dcb {
  strings:
    $key_2dcb = { 7e a4 [2] 5a aa [2] 71 86 [2] 5f a4 [2] 4b bf [2] 44 a5 [2] 5a b8 [2] 58 b9 [2] 43 bf [2] 5f b8 [2] 43 97 }

  condition:
    any of them
}