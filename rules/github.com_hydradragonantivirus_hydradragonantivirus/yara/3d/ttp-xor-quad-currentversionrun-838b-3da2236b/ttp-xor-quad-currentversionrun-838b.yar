rule TTP_XOR_QUAD_CurrentVersionRun_838b {
  strings:
    $key_838b = { d0 e4 [2] f4 ea [2] df c6 [2] f1 e4 [2] e5 ff [2] ea e5 [2] f4 f8 [2] f6 f9 [2] ed ff [2] f1 f8 [2] ed d7 }

  condition:
    any of them
}