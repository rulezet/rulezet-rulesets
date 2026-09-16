rule TTP_XOR_QUAD_CurrentVersionRun_963b {
  strings:
    $key_963b = { c5 54 [2] e1 5a [2] ca 76 [2] e4 54 [2] f0 4f [2] ff 55 [2] e1 48 [2] e3 49 [2] f8 4f [2] e4 48 [2] f8 67 }

  condition:
    any of them
}