rule TTP_XOR_QUAD_CurrentVersionRun_9617 {
  strings:
    $key_9617 = { c5 78 [2] e1 76 [2] ca 5a [2] e4 78 [2] f0 63 [2] ff 79 [2] e1 64 [2] e3 65 [2] f8 63 [2] e4 64 [2] f8 4b }

  condition:
    any of them
}