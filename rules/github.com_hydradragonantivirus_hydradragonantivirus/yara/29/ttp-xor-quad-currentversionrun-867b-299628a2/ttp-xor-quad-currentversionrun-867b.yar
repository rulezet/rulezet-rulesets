rule TTP_XOR_QUAD_CurrentVersionRun_867b {
  strings:
    $key_867b = { d5 14 [2] f1 1a [2] da 36 [2] f4 14 [2] e0 0f [2] ef 15 [2] f1 08 [2] f3 09 [2] e8 0f [2] f4 08 [2] e8 27 }

  condition:
    any of them
}