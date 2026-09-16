rule TTP_XOR_QUAD_CurrentVersionRun_13d0 {
  strings:
    $key_13d0 = { 40 bf [2] 64 b1 [2] 4f 9d [2] 61 bf [2] 75 a4 [2] 7a be [2] 64 a3 [2] 66 a2 [2] 7d a4 [2] 61 a3 [2] 7d 8c }

  condition:
    any of them
}