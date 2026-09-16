rule TTP_XOR_QUAD_CurrentVersionRun_9637 {
  strings:
    $key_9637 = { c5 58 [2] e1 56 [2] ca 7a [2] e4 58 [2] f0 43 [2] ff 59 [2] e1 44 [2] e3 45 [2] f8 43 [2] e4 44 [2] f8 6b }

  condition:
    any of them
}