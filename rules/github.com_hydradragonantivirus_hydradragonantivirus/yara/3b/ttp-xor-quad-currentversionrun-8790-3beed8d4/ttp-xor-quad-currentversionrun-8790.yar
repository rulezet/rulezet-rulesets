rule TTP_XOR_QUAD_CurrentVersionRun_8790 {
  strings:
    $key_8790 = { d4 ff [2] f0 f1 [2] db dd [2] f5 ff [2] e1 e4 [2] ee fe [2] f0 e3 [2] f2 e2 [2] e9 e4 [2] f5 e3 [2] e9 cc }

  condition:
    any of them
}