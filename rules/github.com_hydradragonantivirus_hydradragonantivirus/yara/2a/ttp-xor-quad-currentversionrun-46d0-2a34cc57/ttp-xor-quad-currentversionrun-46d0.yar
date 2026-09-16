rule TTP_XOR_QUAD_CurrentVersionRun_46d0 {
  strings:
    $key_46d0 = { 15 bf [2] 31 b1 [2] 1a 9d [2] 34 bf [2] 20 a4 [2] 2f be [2] 31 a3 [2] 33 a2 [2] 28 a4 [2] 34 a3 [2] 28 8c }

  condition:
    any of them
}