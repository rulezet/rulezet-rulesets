rule TTP_XOR_QUAD_CurrentVersionRun_8491 {
  strings:
    $key_8491 = { d7 fe [2] f3 f0 [2] d8 dc [2] f6 fe [2] e2 e5 [2] ed ff [2] f3 e2 [2] f1 e3 [2] ea e5 [2] f6 e2 [2] ea cd }

  condition:
    any of them
}