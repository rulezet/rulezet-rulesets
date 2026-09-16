rule TTP_XOR_QUAD_CurrentVersionRun_8d06 {
  strings:
    $key_8d06 = { de 69 [2] fa 67 [2] d1 4b [2] ff 69 [2] eb 72 [2] e4 68 [2] fa 75 [2] f8 74 [2] e3 72 [2] ff 75 [2] e3 5a }

  condition:
    any of them
}