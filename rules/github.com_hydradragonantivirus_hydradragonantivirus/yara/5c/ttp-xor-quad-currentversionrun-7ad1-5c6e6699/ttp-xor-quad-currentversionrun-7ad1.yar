rule TTP_XOR_QUAD_CurrentVersionRun_7ad1 {
  strings:
    $key_7ad1 = { 29 be [2] 0d b0 [2] 26 9c [2] 08 be [2] 1c a5 [2] 13 bf [2] 0d a2 [2] 0f a3 [2] 14 a5 [2] 08 a2 [2] 14 8d }

  condition:
    any of them
}