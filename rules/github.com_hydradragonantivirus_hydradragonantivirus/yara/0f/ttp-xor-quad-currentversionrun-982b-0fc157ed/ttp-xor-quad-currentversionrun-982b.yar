rule TTP_XOR_QUAD_CurrentVersionRun_982b {
  strings:
    $key_982b = { cb 44 [2] ef 4a [2] c4 66 [2] ea 44 [2] fe 5f [2] f1 45 [2] ef 58 [2] ed 59 [2] f6 5f [2] ea 58 [2] f6 77 }

  condition:
    any of them
}