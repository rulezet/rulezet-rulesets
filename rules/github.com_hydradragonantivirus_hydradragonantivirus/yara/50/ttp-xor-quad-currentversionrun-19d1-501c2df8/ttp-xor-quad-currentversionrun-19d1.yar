rule TTP_XOR_QUAD_CurrentVersionRun_19d1 {
  strings:
    $key_19d1 = { 4a be [2] 6e b0 [2] 45 9c [2] 6b be [2] 7f a5 [2] 70 bf [2] 6e a2 [2] 6c a3 [2] 77 a5 [2] 6b a2 [2] 77 8d }

  condition:
    any of them
}