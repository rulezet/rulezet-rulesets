rule TTP_XOR_QUAD_CurrentVersionRun_51d0 {
  strings:
    $key_51d0 = { 02 bf [2] 26 b1 [2] 0d 9d [2] 23 bf [2] 37 a4 [2] 38 be [2] 26 a3 [2] 24 a2 [2] 3f a4 [2] 23 a3 [2] 3f 8c }

  condition:
    any of them
}