rule TTP_XOR_QUAD_CurrentVersionRun_8d24 {
  strings:
    $key_8d24 = { de 4b [2] fa 45 [2] d1 69 [2] ff 4b [2] eb 50 [2] e4 4a [2] fa 57 [2] f8 56 [2] e3 50 [2] ff 57 [2] e3 78 }

  condition:
    any of them
}