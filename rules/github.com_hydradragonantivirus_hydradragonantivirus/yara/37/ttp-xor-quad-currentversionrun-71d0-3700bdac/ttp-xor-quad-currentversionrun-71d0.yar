rule TTP_XOR_QUAD_CurrentVersionRun_71d0 {
  strings:
    $key_71d0 = { 22 bf [2] 06 b1 [2] 2d 9d [2] 03 bf [2] 17 a4 [2] 18 be [2] 06 a3 [2] 04 a2 [2] 1f a4 [2] 03 a3 [2] 1f 8c }

  condition:
    any of them
}