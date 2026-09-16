rule TTP_XOR_QUAD_CurrentVersionRun_55d0 {
  strings:
    $key_55d0 = { 06 bf [2] 22 b1 [2] 09 9d [2] 27 bf [2] 33 a4 [2] 3c be [2] 22 a3 [2] 20 a2 [2] 3b a4 [2] 27 a3 [2] 3b 8c }

  condition:
    any of them
}