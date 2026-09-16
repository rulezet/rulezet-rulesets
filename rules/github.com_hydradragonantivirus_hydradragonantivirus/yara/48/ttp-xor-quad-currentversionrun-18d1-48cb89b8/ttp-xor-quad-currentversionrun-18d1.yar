rule TTP_XOR_QUAD_CurrentVersionRun_18d1 {
  strings:
    $key_18d1 = { 4b be [2] 6f b0 [2] 44 9c [2] 6a be [2] 7e a5 [2] 71 bf [2] 6f a2 [2] 6d a3 [2] 76 a5 [2] 6a a2 [2] 76 8d }

  condition:
    any of them
}