rule TTP_XOR_QUAD_CurrentVersionRun_8d29 {
  strings:
    $key_8d29 = { de 46 [2] fa 48 [2] d1 64 [2] ff 46 [2] eb 5d [2] e4 47 [2] fa 5a [2] f8 5b [2] e3 5d [2] ff 5a [2] e3 75 }

  condition:
    any of them
}