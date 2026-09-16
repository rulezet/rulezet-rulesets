rule TTP_XOR_QUAD_CurrentVersionRun_8296 {
  strings:
    $key_8296 = { d1 f9 [2] f5 f7 [2] de db [2] f0 f9 [2] e4 e2 [2] eb f8 [2] f5 e5 [2] f7 e4 [2] ec e2 [2] f0 e5 [2] ec ca }

  condition:
    any of them
}