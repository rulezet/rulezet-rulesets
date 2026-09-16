rule TTP_XOR_QUAD_CurrentVersionRun_9638 {
  strings:
    $key_9638 = { c5 57 [2] e1 59 [2] ca 75 [2] e4 57 [2] f0 4c [2] ff 56 [2] e1 4b [2] e3 4a [2] f8 4c [2] e4 4b [2] f8 64 }

  condition:
    any of them
}