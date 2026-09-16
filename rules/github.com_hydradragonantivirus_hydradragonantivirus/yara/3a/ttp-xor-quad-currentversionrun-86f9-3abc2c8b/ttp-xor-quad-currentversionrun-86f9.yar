rule TTP_XOR_QUAD_CurrentVersionRun_86f9 {
  strings:
    $key_86f9 = { d5 96 [2] f1 98 [2] da b4 [2] f4 96 [2] e0 8d [2] ef 97 [2] f1 8a [2] f3 8b [2] e8 8d [2] f4 8a [2] e8 a5 }

  condition:
    any of them
}