rule TTP_XOR_QUAD_CurrentVersionRun_95db {
  strings:
    $key_95db = { c6 b4 [2] e2 ba [2] c9 96 [2] e7 b4 [2] f3 af [2] fc b5 [2] e2 a8 [2] e0 a9 [2] fb af [2] e7 a8 [2] fb 87 }

  condition:
    any of them
}