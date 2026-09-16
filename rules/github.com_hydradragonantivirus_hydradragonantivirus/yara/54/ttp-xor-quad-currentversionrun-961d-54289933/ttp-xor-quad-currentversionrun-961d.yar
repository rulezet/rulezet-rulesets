rule TTP_XOR_QUAD_CurrentVersionRun_961d {
  strings:
    $key_961d = { c5 72 [2] e1 7c [2] ca 50 [2] e4 72 [2] f0 69 [2] ff 73 [2] e1 6e [2] e3 6f [2] f8 69 [2] e4 6e [2] f8 41 }

  condition:
    any of them
}