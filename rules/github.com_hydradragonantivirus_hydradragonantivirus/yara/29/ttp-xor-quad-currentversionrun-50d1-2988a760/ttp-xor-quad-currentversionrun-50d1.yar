rule TTP_XOR_QUAD_CurrentVersionRun_50d1 {
  strings:
    $key_50d1 = { 03 be [2] 27 b0 [2] 0c 9c [2] 22 be [2] 36 a5 [2] 39 bf [2] 27 a2 [2] 25 a3 [2] 3e a5 [2] 22 a2 [2] 3e 8d }

  condition:
    any of them
}