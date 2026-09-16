rule TTP_XOR_QUAD_CurrentVersionRun_70d1 {
  strings:
    $key_70d1 = { 23 be [2] 07 b0 [2] 2c 9c [2] 02 be [2] 16 a5 [2] 19 bf [2] 07 a2 [2] 05 a3 [2] 1e a5 [2] 02 a2 [2] 1e 8d }

  condition:
    any of them
}