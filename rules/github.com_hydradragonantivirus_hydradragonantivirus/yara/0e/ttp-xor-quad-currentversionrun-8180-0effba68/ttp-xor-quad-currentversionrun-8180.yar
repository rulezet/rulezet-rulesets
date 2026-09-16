rule TTP_XOR_QUAD_CurrentVersionRun_8180 {
  strings:
    $key_8180 = { d2 ef [2] f6 e1 [2] dd cd [2] f3 ef [2] e7 f4 [2] e8 ee [2] f6 f3 [2] f4 f2 [2] ef f4 [2] f3 f3 [2] ef dc }

  condition:
    any of them
}