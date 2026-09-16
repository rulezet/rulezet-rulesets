rule TTP_XOR_QUAD_CurrentVersionRun_98e6 {
  strings:
    $key_98e6 = { cb 89 [2] ef 87 [2] c4 ab [2] ea 89 [2] fe 92 [2] f1 88 [2] ef 95 [2] ed 94 [2] f6 92 [2] ea 95 [2] f6 ba }

  condition:
    any of them
}