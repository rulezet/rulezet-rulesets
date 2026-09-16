rule TTP_XOR_QUAD_CurrentVersionRun_5dd1 {
  strings:
    $key_5dd1 = { 0e be [2] 2a b0 [2] 01 9c [2] 2f be [2] 3b a5 [2] 34 bf [2] 2a a2 [2] 28 a3 [2] 33 a5 [2] 2f a2 [2] 33 8d }

  condition:
    any of them
}