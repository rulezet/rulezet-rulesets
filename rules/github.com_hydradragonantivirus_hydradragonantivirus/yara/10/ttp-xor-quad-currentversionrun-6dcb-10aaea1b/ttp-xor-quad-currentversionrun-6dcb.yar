rule TTP_XOR_QUAD_CurrentVersionRun_6dcb {
  strings:
    $key_6dcb = { 3e a4 [2] 1a aa [2] 31 86 [2] 1f a4 [2] 0b bf [2] 04 a5 [2] 1a b8 [2] 18 b9 [2] 03 bf [2] 1f b8 [2] 03 97 }

  condition:
    any of them
}