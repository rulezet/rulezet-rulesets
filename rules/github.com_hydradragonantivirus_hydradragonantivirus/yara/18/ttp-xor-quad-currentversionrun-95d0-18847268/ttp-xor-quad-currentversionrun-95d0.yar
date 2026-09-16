rule TTP_XOR_QUAD_CurrentVersionRun_95d0 {
  strings:
    $key_95d0 = { c6 bf [2] e2 b1 [2] c9 9d [2] e7 bf [2] f3 a4 [2] fc be [2] e2 a3 [2] e0 a2 [2] fb a4 [2] e7 a3 [2] fb 8c }

  condition:
    any of them
}