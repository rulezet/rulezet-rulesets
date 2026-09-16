rule TTP_XOR_QUAD_CurrentVersionRun_2dd1 {
  strings:
    $key_2dd1 = { 7e be [2] 5a b0 [2] 71 9c [2] 5f be [2] 4b a5 [2] 44 bf [2] 5a a2 [2] 58 a3 [2] 43 a5 [2] 5f a2 [2] 43 8d }

  condition:
    any of them
}