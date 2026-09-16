rule TTP_XOR_QUAD_CurrentVersionRun_6bd1 {
  strings:
    $key_6bd1 = { 38 be [2] 1c b0 [2] 37 9c [2] 19 be [2] 0d a5 [2] 02 bf [2] 1c a2 [2] 1e a3 [2] 05 a5 [2] 19 a2 [2] 05 8d }

  condition:
    any of them
}