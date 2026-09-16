rule TTP_XOR_QUAD_CurrentVersionRun_29d1 {
  strings:
    $key_29d1 = { 7a be [2] 5e b0 [2] 75 9c [2] 5b be [2] 4f a5 [2] 40 bf [2] 5e a2 [2] 5c a3 [2] 47 a5 [2] 5b a2 [2] 47 8d }

  condition:
    any of them
}