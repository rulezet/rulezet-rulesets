rule TTP_XOR_QUAD_CurrentVersionRun_e2d0 {
  strings:
    $key_e2d0 = { b1 bf [2] 95 b1 [2] be 9d [2] 90 bf [2] 84 a4 [2] 8b be [2] 95 a3 [2] 97 a2 [2] 8c a4 [2] 90 a3 [2] 8c 8c }

  condition:
    any of them
}