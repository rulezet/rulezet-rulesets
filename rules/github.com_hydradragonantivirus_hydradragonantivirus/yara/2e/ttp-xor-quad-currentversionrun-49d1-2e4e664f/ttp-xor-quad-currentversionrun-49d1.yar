rule TTP_XOR_QUAD_CurrentVersionRun_49d1 {
  strings:
    $key_49d1 = { 1a be [2] 3e b0 [2] 15 9c [2] 3b be [2] 2f a5 [2] 20 bf [2] 3e a2 [2] 3c a3 [2] 27 a5 [2] 3b a2 [2] 27 8d }

  condition:
    any of them
}