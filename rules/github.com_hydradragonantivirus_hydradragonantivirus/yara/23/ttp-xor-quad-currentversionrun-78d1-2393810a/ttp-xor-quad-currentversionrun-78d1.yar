rule TTP_XOR_QUAD_CurrentVersionRun_78d1 {
  strings:
    $key_78d1 = { 2b be [2] 0f b0 [2] 24 9c [2] 0a be [2] 1e a5 [2] 11 bf [2] 0f a2 [2] 0d a3 [2] 16 a5 [2] 0a a2 [2] 16 8d }

  condition:
    any of them
}