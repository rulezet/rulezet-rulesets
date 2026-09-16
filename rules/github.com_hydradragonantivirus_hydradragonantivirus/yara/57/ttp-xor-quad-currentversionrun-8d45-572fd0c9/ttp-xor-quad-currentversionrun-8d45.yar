rule TTP_XOR_QUAD_CurrentVersionRun_8d45 {
  strings:
    $key_8d45 = { de 2a [2] fa 24 [2] d1 08 [2] ff 2a [2] eb 31 [2] e4 2b [2] fa 36 [2] f8 37 [2] e3 31 [2] ff 36 [2] e3 19 }

  condition:
    any of them
}