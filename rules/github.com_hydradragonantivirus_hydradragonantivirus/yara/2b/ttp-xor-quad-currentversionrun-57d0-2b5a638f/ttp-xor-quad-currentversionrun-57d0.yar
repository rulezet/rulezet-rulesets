rule TTP_XOR_QUAD_CurrentVersionRun_57d0 {
  strings:
    $key_57d0 = { 04 bf [2] 20 b1 [2] 0b 9d [2] 25 bf [2] 31 a4 [2] 3e be [2] 20 a3 [2] 22 a2 [2] 39 a4 [2] 25 a3 [2] 39 8c }

  condition:
    any of them
}