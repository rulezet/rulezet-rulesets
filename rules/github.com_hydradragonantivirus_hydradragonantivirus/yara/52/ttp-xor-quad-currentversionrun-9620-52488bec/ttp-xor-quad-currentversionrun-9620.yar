rule TTP_XOR_QUAD_CurrentVersionRun_9620 {
  strings:
    $key_9620 = { c5 4f [2] e1 41 [2] ca 6d [2] e4 4f [2] f0 54 [2] ff 4e [2] e1 53 [2] e3 52 [2] f8 54 [2] e4 53 [2] f8 7c }

  condition:
    any of them
}