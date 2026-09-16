rule TTP_XOR_QUAD_CurrentVersionRun_9816 {
  strings:
    $key_9816 = { cb 79 [2] ef 77 [2] c4 5b [2] ea 79 [2] fe 62 [2] f1 78 [2] ef 65 [2] ed 64 [2] f6 62 [2] ea 65 [2] f6 4a }

  condition:
    any of them
}