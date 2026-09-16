rule TTP_XOR_QUAD_CurrentVersionRun_86fd {
  strings:
    $key_86fd = { d5 92 [2] f1 9c [2] da b0 [2] f4 92 [2] e0 89 [2] ef 93 [2] f1 8e [2] f3 8f [2] e8 89 [2] f4 8e [2] e8 a1 }

  condition:
    any of them
}