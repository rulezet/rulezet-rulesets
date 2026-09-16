rule TTP_XOR_QUAD_CurrentVersionRun_9611 {
  strings:
    $key_9611 = { c5 7e [2] e1 70 [2] ca 5c [2] e4 7e [2] f0 65 [2] ff 7f [2] e1 62 [2] e3 63 [2] f8 65 [2] e4 62 [2] f8 4d }

  condition:
    any of them
}