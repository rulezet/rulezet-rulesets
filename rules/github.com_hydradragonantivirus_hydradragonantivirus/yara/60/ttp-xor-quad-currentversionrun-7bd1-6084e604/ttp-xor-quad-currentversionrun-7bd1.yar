rule TTP_XOR_QUAD_CurrentVersionRun_7bd1 {
  strings:
    $key_7bd1 = { 28 be [2] 0c b0 [2] 27 9c [2] 09 be [2] 1d a5 [2] 12 bf [2] 0c a2 [2] 0e a3 [2] 15 a5 [2] 09 a2 [2] 15 8d }

  condition:
    any of them
}