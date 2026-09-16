rule TTP_XOR_QUAD_CurrentVersionRun_98e8 {
  strings:
    $key_98e8 = { cb 87 [2] ef 89 [2] c4 a5 [2] ea 87 [2] fe 9c [2] f1 86 [2] ef 9b [2] ed 9a [2] f6 9c [2] ea 9b [2] f6 b4 }

  condition:
    any of them
}