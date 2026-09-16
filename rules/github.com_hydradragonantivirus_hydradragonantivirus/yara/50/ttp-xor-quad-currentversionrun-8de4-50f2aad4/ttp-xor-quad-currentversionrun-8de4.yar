rule TTP_XOR_QUAD_CurrentVersionRun_8de4 {
  strings:
    $key_8de4 = { de 8b [2] fa 85 [2] d1 a9 [2] ff 8b [2] eb 90 [2] e4 8a [2] fa 97 [2] f8 96 [2] e3 90 [2] ff 97 [2] e3 b8 }

  condition:
    any of them
}