rule TTP_XOR_QUAD_CurrentVersionRun_8d68 {
  strings:
    $key_8d68 = { de 07 [2] fa 09 [2] d1 25 [2] ff 07 [2] eb 1c [2] e4 06 [2] fa 1b [2] f8 1a [2] e3 1c [2] ff 1b [2] e3 34 }

  condition:
    any of them
}