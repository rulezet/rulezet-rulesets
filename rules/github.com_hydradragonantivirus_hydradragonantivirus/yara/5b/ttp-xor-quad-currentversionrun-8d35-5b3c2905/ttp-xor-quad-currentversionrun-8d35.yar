rule TTP_XOR_QUAD_CurrentVersionRun_8d35 {
  strings:
    $key_8d35 = { de 5a [2] fa 54 [2] d1 78 [2] ff 5a [2] eb 41 [2] e4 5b [2] fa 46 [2] f8 47 [2] e3 41 [2] ff 46 [2] e3 69 }

  condition:
    any of them
}