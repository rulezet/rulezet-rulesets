rule TTP_XOR_QUAD_CurrentVersionRun_4dd1 {
  strings:
    $key_4dd1 = { 1e be [2] 3a b0 [2] 11 9c [2] 3f be [2] 2b a5 [2] 24 bf [2] 3a a2 [2] 38 a3 [2] 23 a5 [2] 3f a2 [2] 23 8d }

  condition:
    any of them
}