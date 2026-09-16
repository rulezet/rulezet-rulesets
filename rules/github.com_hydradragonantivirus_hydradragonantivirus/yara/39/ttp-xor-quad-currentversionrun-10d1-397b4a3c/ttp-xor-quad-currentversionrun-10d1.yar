rule TTP_XOR_QUAD_CurrentVersionRun_10d1 {
  strings:
    $key_10d1 = { 43 be [2] 67 b0 [2] 4c 9c [2] 62 be [2] 76 a5 [2] 79 bf [2] 67 a2 [2] 65 a3 [2] 7e a5 [2] 62 a2 [2] 7e 8d }

  condition:
    any of them
}