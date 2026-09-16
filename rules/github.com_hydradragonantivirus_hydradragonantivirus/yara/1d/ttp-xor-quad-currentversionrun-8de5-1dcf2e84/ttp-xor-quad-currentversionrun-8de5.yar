rule TTP_XOR_QUAD_CurrentVersionRun_8de5 {
  strings:
    $key_8de5 = { de 8a [2] fa 84 [2] d1 a8 [2] ff 8a [2] eb 91 [2] e4 8b [2] fa 96 [2] f8 97 [2] e3 91 [2] ff 96 [2] e3 b9 }

  condition:
    any of them
}