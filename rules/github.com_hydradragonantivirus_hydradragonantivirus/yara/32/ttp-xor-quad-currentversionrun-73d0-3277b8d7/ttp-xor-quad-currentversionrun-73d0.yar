rule TTP_XOR_QUAD_CurrentVersionRun_73d0 {
  strings:
    $key_73d0 = { 20 bf [2] 04 b1 [2] 2f 9d [2] 01 bf [2] 15 a4 [2] 1a be [2] 04 a3 [2] 06 a2 [2] 1d a4 [2] 01 a3 [2] 1d 8c }

  condition:
    any of them
}