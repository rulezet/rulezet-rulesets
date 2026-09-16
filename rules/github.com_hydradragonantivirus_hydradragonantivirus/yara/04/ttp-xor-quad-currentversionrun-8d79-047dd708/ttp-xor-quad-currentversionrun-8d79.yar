rule TTP_XOR_QUAD_CurrentVersionRun_8d79 {
  strings:
    $key_8d79 = { de 16 [2] fa 18 [2] d1 34 [2] ff 16 [2] eb 0d [2] e4 17 [2] fa 0a [2] f8 0b [2] e3 0d [2] ff 0a [2] e3 25 }

  condition:
    any of them
}