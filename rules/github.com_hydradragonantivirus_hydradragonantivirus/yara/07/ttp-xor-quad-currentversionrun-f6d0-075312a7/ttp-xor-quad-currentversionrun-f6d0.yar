rule TTP_XOR_QUAD_CurrentVersionRun_f6d0 {
  strings:
    $key_f6d0 = { a5 bf [2] 81 b1 [2] aa 9d [2] 84 bf [2] 90 a4 [2] 9f be [2] 81 a3 [2] 83 a2 [2] 98 a4 [2] 84 a3 [2] 98 8c }

  condition:
    any of them
}