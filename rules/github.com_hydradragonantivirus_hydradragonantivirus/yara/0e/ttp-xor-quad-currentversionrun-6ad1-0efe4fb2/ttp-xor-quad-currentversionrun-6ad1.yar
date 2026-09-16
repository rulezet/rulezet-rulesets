rule TTP_XOR_QUAD_CurrentVersionRun_6ad1 {
  strings:
    $key_6ad1 = { 39 be [2] 1d b0 [2] 36 9c [2] 18 be [2] 0c a5 [2] 03 bf [2] 1d a2 [2] 1f a3 [2] 04 a5 [2] 18 a2 [2] 04 8d }

  condition:
    any of them
}