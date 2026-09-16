rule TTP_XOR_QUAD_CurrentVersionRun_8d48 {
  strings:
    $key_8d48 = { de 27 [2] fa 29 [2] d1 05 [2] ff 27 [2] eb 3c [2] e4 26 [2] fa 3b [2] f8 3a [2] e3 3c [2] ff 3b [2] e3 14 }

  condition:
    any of them
}