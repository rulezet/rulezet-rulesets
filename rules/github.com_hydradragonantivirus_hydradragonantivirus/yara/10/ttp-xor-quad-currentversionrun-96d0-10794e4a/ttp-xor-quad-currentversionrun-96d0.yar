rule TTP_XOR_QUAD_CurrentVersionRun_96d0 {
  strings:
    $key_96d0 = { c5 bf [2] e1 b1 [2] ca 9d [2] e4 bf [2] f0 a4 [2] ff be [2] e1 a3 [2] e3 a2 [2] f8 a4 [2] e4 a3 [2] f8 8c }

  condition:
    any of them
}