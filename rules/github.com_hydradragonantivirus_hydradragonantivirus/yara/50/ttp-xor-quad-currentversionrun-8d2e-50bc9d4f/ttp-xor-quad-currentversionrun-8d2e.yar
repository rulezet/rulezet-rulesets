rule TTP_XOR_QUAD_CurrentVersionRun_8d2e {
  strings:
    $key_8d2e = { de 41 [2] fa 4f [2] d1 63 [2] ff 41 [2] eb 5a [2] e4 40 [2] fa 5d [2] f8 5c [2] e3 5a [2] ff 5d [2] e3 72 }

  condition:
    any of them
}