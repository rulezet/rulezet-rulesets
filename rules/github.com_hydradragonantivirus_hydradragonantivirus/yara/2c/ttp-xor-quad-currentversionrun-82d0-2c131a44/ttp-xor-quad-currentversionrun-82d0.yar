rule TTP_XOR_QUAD_CurrentVersionRun_82d0 {
  strings:
    $key_82d0 = { d1 bf [2] f5 b1 [2] de 9d [2] f0 bf [2] e4 a4 [2] eb be [2] f5 a3 [2] f7 a2 [2] ec a4 [2] f0 a3 [2] ec 8c }

  condition:
    any of them
}