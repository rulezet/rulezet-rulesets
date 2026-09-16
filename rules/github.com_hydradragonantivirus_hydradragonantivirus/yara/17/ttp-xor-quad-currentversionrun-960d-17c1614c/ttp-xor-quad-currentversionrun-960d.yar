rule TTP_XOR_QUAD_CurrentVersionRun_960d {
  strings:
    $key_960d = { c5 62 [2] e1 6c [2] ca 40 [2] e4 62 [2] f0 79 [2] ff 63 [2] e1 7e [2] e3 7f [2] f8 79 [2] e4 7e [2] f8 51 }

  condition:
    any of them
}