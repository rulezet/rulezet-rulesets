rule TTP_XOR_QUAD_CurrentVersionRun_86ed {
  strings:
    $key_86ed = { d5 82 [2] f1 8c [2] da a0 [2] f4 82 [2] e0 99 [2] ef 83 [2] f1 9e [2] f3 9f [2] e8 99 [2] f4 9e [2] e8 b1 }

  condition:
    any of them
}