rule TTP_XOR_QUAD_CurrentVersionRun_1bd1 {
  strings:
    $key_1bd1 = { 48 be [2] 6c b0 [2] 47 9c [2] 69 be [2] 7d a5 [2] 72 bf [2] 6c a2 [2] 6e a3 [2] 75 a5 [2] 69 a2 [2] 75 8d }

  condition:
    any of them
}