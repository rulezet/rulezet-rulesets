rule TTP_XOR_QUAD_CurrentVersionRun_ead0 {
  strings:
    $key_ead0 = { b9 bf [2] 9d b1 [2] b6 9d [2] 98 bf [2] 8c a4 [2] 83 be [2] 9d a3 [2] 9f a2 [2] 84 a4 [2] 98 a3 [2] 84 8c }

  condition:
    any of them
}