rule TTP_XOR_QUAD_CurrentVersionRun_962f {
  strings:
    $key_962f = { c5 40 [2] e1 4e [2] ca 62 [2] e4 40 [2] f0 5b [2] ff 41 [2] e1 5c [2] e3 5d [2] f8 5b [2] e4 5c [2] f8 73 }

  condition:
    any of them
}