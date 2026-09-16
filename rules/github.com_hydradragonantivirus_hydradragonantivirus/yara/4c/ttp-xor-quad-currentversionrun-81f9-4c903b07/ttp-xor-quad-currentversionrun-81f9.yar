rule TTP_XOR_QUAD_CurrentVersionRun_81f9 {
  strings:
    $key_81f9 = { d2 96 [2] f6 98 [2] dd b4 [2] f3 96 [2] e7 8d [2] e8 97 [2] f6 8a [2] f4 8b [2] ef 8d [2] f3 8a [2] ef a5 }

  condition:
    any of them
}