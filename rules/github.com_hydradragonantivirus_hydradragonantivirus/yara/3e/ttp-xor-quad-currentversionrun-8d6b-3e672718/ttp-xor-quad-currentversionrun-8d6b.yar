rule TTP_XOR_QUAD_CurrentVersionRun_8d6b {
  strings:
    $key_8d6b = { de 04 [2] fa 0a [2] d1 26 [2] ff 04 [2] eb 1f [2] e4 05 [2] fa 18 [2] f8 19 [2] e3 1f [2] ff 18 [2] e3 37 }

  condition:
    any of them
}