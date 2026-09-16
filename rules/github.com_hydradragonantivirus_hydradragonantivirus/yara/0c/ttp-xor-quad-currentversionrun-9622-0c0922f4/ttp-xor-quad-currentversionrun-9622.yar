rule TTP_XOR_QUAD_CurrentVersionRun_9622 {
  strings:
    $key_9622 = { c5 4d [2] e1 43 [2] ca 6f [2] e4 4d [2] f0 56 [2] ff 4c [2] e1 51 [2] e3 50 [2] f8 56 [2] e4 51 [2] f8 7e }

  condition:
    any of them
}