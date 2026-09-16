rule TTP_XOR_QUAD_CurrentVersionRun_963d {
  strings:
    $key_963d = { c5 52 [2] e1 5c [2] ca 70 [2] e4 52 [2] f0 49 [2] ff 53 [2] e1 4e [2] e3 4f [2] f8 49 [2] e4 4e [2] f8 61 }

  condition:
    any of them
}