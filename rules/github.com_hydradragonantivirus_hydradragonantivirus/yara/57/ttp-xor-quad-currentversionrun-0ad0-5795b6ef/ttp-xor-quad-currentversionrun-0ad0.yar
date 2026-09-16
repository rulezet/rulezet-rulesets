rule TTP_XOR_QUAD_CurrentVersionRun_0ad0 {
  strings:
    $key_0ad0 = { 59 bf [2] 7d b1 [2] 56 9d [2] 78 bf [2] 6c a4 [2] 63 be [2] 7d a3 [2] 7f a2 [2] 64 a4 [2] 78 a3 [2] 64 8c }

  condition:
    any of them
}