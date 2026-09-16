rule TTP_XOR_QUAD_CurrentVersionRun_960c {
  strings:
    $key_960c = { c5 63 [2] e1 6d [2] ca 41 [2] e4 63 [2] f0 78 [2] ff 62 [2] e1 7f [2] e3 7e [2] f8 78 [2] e4 7f [2] f8 50 }

  condition:
    any of them
}