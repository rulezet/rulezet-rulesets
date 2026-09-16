rule TTP_XOR_QUAD_CurrentVersionRun_8190 {
  strings:
    $key_8190 = { d2 ff [2] f6 f1 [2] dd dd [2] f3 ff [2] e7 e4 [2] e8 fe [2] f6 e3 [2] f4 e2 [2] ef e4 [2] f3 e3 [2] ef cc }

  condition:
    any of them
}