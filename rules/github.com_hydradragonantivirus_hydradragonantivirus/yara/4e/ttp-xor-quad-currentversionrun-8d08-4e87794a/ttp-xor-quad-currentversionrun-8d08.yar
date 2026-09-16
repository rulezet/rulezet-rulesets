rule TTP_XOR_QUAD_CurrentVersionRun_8d08 {
  strings:
    $key_8d08 = { de 67 [2] fa 69 [2] d1 45 [2] ff 67 [2] eb 7c [2] e4 66 [2] fa 7b [2] f8 7a [2] e3 7c [2] ff 7b [2] e3 54 }

  condition:
    any of them
}