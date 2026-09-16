rule TTP_XOR_QUAD_CurrentVersionRun_9606 {
  strings:
    $key_9606 = { c5 69 [2] e1 67 [2] ca 4b [2] e4 69 [2] f0 72 [2] ff 68 [2] e1 75 [2] e3 74 [2] f8 72 [2] e4 75 [2] f8 5a }

  condition:
    any of them
}