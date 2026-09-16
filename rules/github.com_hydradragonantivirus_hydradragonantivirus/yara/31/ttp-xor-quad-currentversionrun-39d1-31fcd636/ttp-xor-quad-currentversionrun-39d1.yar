rule TTP_XOR_QUAD_CurrentVersionRun_39d1 {
  strings:
    $key_39d1 = { 6a be [2] 4e b0 [2] 65 9c [2] 4b be [2] 5f a5 [2] 50 bf [2] 4e a2 [2] 4c a3 [2] 57 a5 [2] 4b a2 [2] 57 8d }

  condition:
    any of them
}