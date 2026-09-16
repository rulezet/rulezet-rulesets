rule TTP_XOR_QUAD_CurrentVersionRun_9836 {
  strings:
    $key_9836 = { cb 59 [2] ef 57 [2] c4 7b [2] ea 59 [2] fe 42 [2] f1 58 [2] ef 45 [2] ed 44 [2] f6 42 [2] ea 45 [2] f6 6a }

  condition:
    any of them
}