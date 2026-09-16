rule TTP_XOR_QUAD_CurrentVersionRun_9809 {
  strings:
    $key_9809 = { cb 66 [2] ef 68 [2] c4 44 [2] ea 66 [2] fe 7d [2] f1 67 [2] ef 7a [2] ed 7b [2] f6 7d [2] ea 7a [2] f6 55 }

  condition:
    any of them
}