rule TTP_XOR_QUAD_CurrentVersionRun_50d0 {
  strings:
    $key_50d0 = { 03 bf [2] 27 b1 [2] 0c 9d [2] 22 bf [2] 36 a4 [2] 39 be [2] 27 a3 [2] 25 a2 [2] 3e a4 [2] 22 a3 [2] 3e 8c }

  condition:
    any of them
}