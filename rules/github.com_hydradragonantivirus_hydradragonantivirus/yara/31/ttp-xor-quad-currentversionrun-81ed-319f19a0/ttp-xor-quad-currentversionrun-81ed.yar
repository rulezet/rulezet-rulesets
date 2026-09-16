rule TTP_XOR_QUAD_CurrentVersionRun_81ed {
  strings:
    $key_81ed = { d2 82 [2] f6 8c [2] dd a0 [2] f3 82 [2] e7 99 [2] e8 83 [2] f6 9e [2] f4 9f [2] ef 99 [2] f3 9e [2] ef b1 }

  condition:
    any of them
}