rule TTP_XOR_QUAD_CurrentVersionRun_30d0 {
  strings:
    $key_30d0 = { 63 bf [2] 47 b1 [2] 6c 9d [2] 42 bf [2] 56 a4 [2] 59 be [2] 47 a3 [2] 45 a2 [2] 5e a4 [2] 42 a3 [2] 5e 8c }

  condition:
    any of them
}