rule TTP_XOR_QUAD_CurrentVersionRun_21d0 {
  strings:
    $key_21d0 = { 72 bf [2] 56 b1 [2] 7d 9d [2] 53 bf [2] 47 a4 [2] 48 be [2] 56 a3 [2] 54 a2 [2] 4f a4 [2] 53 a3 [2] 4f 8c }

  condition:
    any of them
}