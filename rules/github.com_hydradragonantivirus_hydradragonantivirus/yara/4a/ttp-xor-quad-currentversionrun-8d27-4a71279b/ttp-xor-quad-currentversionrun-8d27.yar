rule TTP_XOR_QUAD_CurrentVersionRun_8d27 {
  strings:
    $key_8d27 = { de 48 [2] fa 46 [2] d1 6a [2] ff 48 [2] eb 53 [2] e4 49 [2] fa 54 [2] f8 55 [2] e3 53 [2] ff 54 [2] e3 7b }

  condition:
    any of them
}