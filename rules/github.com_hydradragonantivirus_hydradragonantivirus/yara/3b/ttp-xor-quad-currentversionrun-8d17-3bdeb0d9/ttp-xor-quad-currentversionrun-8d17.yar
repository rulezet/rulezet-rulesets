rule TTP_XOR_QUAD_CurrentVersionRun_8d17 {
  strings:
    $key_8d17 = { de 78 [2] fa 76 [2] d1 5a [2] ff 78 [2] eb 63 [2] e4 79 [2] fa 64 [2] f8 65 [2] e3 63 [2] ff 64 [2] e3 4b }

  condition:
    any of them
}