rule TTP_XOR_QUAD_CurrentVersionRun_8288 {
  strings:
    $key_8288 = { d1 e7 [2] f5 e9 [2] de c5 [2] f0 e7 [2] e4 fc [2] eb e6 [2] f5 fb [2] f7 fa [2] ec fc [2] f0 fb [2] ec d4 }

  condition:
    any of them
}