rule TTP_XOR_QUAD_CurrentVersionRun_8d3b {
  strings:
    $key_8d3b = { de 54 [2] fa 5a [2] d1 76 [2] ff 54 [2] eb 4f [2] e4 55 [2] fa 48 [2] f8 49 [2] e3 4f [2] ff 48 [2] e3 67 }

  condition:
    any of them
}