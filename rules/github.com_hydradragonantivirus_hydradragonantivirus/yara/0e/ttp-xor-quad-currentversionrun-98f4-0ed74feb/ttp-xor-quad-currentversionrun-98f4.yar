rule TTP_XOR_QUAD_CurrentVersionRun_98f4 {
  strings:
    $key_98f4 = { cb 9b [2] ef 95 [2] c4 b9 [2] ea 9b [2] fe 80 [2] f1 9a [2] ef 87 [2] ed 86 [2] f6 80 [2] ea 87 [2] f6 a8 }

  condition:
    any of them
}