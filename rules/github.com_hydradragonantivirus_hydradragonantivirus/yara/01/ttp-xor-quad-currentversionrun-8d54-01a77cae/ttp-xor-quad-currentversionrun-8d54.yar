rule TTP_XOR_QUAD_CurrentVersionRun_8d54 {
  strings:
    $key_8d54 = { de 3b [2] fa 35 [2] d1 19 [2] ff 3b [2] eb 20 [2] e4 3a [2] fa 27 [2] f8 26 [2] e3 20 [2] ff 27 [2] e3 08 }

  condition:
    any of them
}