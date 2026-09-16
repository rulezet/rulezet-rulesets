rule TTP_XOR_QUAD_CurrentVersionRun_8d38 {
  strings:
    $key_8d38 = { de 57 [2] fa 59 [2] d1 75 [2] ff 57 [2] eb 4c [2] e4 56 [2] fa 4b [2] f8 4a [2] e3 4c [2] ff 4b [2] e3 64 }

  condition:
    any of them
}