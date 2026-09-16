rule TTP_XOR_QUAD_CurrentVersionRun_8d65 {
  strings:
    $key_8d65 = { de 0a [2] fa 04 [2] d1 28 [2] ff 0a [2] eb 11 [2] e4 0b [2] fa 16 [2] f8 17 [2] e3 11 [2] ff 16 [2] e3 39 }

  condition:
    any of them
}