rule TTP_XOR_QUAD_CurrentVersionRun_8612 {
  strings:
    $key_8612 = { d5 7d [2] f1 73 [2] da 5f [2] f4 7d [2] e0 66 [2] ef 7c [2] f1 61 [2] f3 60 [2] e8 66 [2] f4 61 [2] e8 4e }

  condition:
    any of them
}