rule TTP_XOR_QUAD_CurrentVersionRun_9660 {
  strings:
    $key_9660 = { c5 0f [2] e1 01 [2] ca 2d [2] e4 0f [2] f0 14 [2] ff 0e [2] e1 13 [2] e3 12 [2] f8 14 [2] e4 13 [2] f8 3c }

  condition:
    any of them
}