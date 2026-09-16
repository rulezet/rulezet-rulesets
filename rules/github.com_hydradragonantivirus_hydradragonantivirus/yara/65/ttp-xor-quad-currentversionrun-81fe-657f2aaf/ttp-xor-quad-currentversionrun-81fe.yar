rule TTP_XOR_QUAD_CurrentVersionRun_81fe {
  strings:
    $key_81fe = { d2 91 [2] f6 9f [2] dd b3 [2] f3 91 [2] e7 8a [2] e8 90 [2] f6 8d [2] f4 8c [2] ef 8a [2] f3 8d [2] ef a2 }

  condition:
    any of them
}