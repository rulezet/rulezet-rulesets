rule TTP_XOR_QUAD_CurrentVersionRun_8d2b {
  strings:
    $key_8d2b = { de 44 [2] fa 4a [2] d1 66 [2] ff 44 [2] eb 5f [2] e4 45 [2] fa 58 [2] f8 59 [2] e3 5f [2] ff 58 [2] e3 77 }

  condition:
    any of them
}