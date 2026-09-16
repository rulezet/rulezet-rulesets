rule TTP_XOR_QUAD_CurrentVersionRun_8d07 {
  strings:
    $key_8d07 = { de 68 [2] fa 66 [2] d1 4a [2] ff 68 [2] eb 73 [2] e4 69 [2] fa 74 [2] f8 75 [2] e3 73 [2] ff 74 [2] e3 5b }

  condition:
    any of them
}