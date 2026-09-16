rule TTP_XOR_QUAD_CurrentVersionRun_37d0 {
  strings:
    $key_37d0 = { 64 bf [2] 40 b1 [2] 6b 9d [2] 45 bf [2] 51 a4 [2] 5e be [2] 40 a3 [2] 42 a2 [2] 59 a4 [2] 45 a3 [2] 59 8c }

  condition:
    any of them
}