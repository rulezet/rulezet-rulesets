rule TTP_XOR_QUAD_CurrentVersionRun_8df8 {
  strings:
    $key_8df8 = { de 97 [2] fa 99 [2] d1 b5 [2] ff 97 [2] eb 8c [2] e4 96 [2] fa 8b [2] f8 8a [2] e3 8c [2] ff 8b [2] e3 a4 }

  condition:
    any of them
}