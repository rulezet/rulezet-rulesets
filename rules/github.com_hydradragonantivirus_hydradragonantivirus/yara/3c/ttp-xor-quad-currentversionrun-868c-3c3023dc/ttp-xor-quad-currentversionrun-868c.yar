rule TTP_XOR_QUAD_CurrentVersionRun_868c {
  strings:
    $key_868c = { d5 e3 [2] f1 ed [2] da c1 [2] f4 e3 [2] e0 f8 [2] ef e2 [2] f1 ff [2] f3 fe [2] e8 f8 [2] f4 ff [2] e8 d0 }

  condition:
    any of them
}