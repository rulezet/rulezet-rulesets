rule TTP_XOR_QUAD_CurrentVersionRun_9604 {
  strings:
    $key_9604 = { c5 6b [2] e1 65 [2] ca 49 [2] e4 6b [2] f0 70 [2] ff 6a [2] e1 77 [2] e3 76 [2] f8 70 [2] e4 77 [2] f8 58 }

  condition:
    any of them
}