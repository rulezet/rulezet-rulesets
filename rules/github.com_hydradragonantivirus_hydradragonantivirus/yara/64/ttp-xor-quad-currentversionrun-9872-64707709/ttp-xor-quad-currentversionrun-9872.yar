rule TTP_XOR_QUAD_CurrentVersionRun_9872 {
  strings:
    $key_9872 = { cb 1d [2] ef 13 [2] c4 3f [2] ea 1d [2] fe 06 [2] f1 1c [2] ef 01 [2] ed 00 [2] f6 06 [2] ea 01 [2] f6 2e }

  condition:
    any of them
}