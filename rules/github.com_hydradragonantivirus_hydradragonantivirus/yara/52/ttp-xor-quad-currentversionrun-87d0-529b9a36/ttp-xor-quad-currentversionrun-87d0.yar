rule TTP_XOR_QUAD_CurrentVersionRun_87d0 {
  strings:
    $key_87d0 = { d4 bf [2] f0 b1 [2] db 9d [2] f5 bf [2] e1 a4 [2] ee be [2] f0 a3 [2] f2 a2 [2] e9 a4 [2] f5 a3 [2] e9 8c }

  condition:
    any of them
}