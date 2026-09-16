rule TTP_XOR_QUAD_CurrentVersionRun_28d1 {
  strings:
    $key_28d1 = { 7b be [2] 5f b0 [2] 74 9c [2] 5a be [2] 4e a5 [2] 41 bf [2] 5f a2 [2] 5d a3 [2] 46 a5 [2] 5a a2 [2] 46 8d }

  condition:
    any of them
}