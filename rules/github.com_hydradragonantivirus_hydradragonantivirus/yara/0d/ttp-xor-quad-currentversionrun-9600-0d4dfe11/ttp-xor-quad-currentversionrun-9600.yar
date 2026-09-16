rule TTP_XOR_QUAD_CurrentVersionRun_9600 {
  strings:
    $key_9600 = { c5 6f [2] e1 61 [2] ca 4d [2] e4 6f [2] f0 74 [2] ff 6e [2] e1 73 [2] e3 72 [2] f8 74 [2] e4 73 [2] f8 5c }

  condition:
    any of them
}