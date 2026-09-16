rule TTP_XOR_QUAD_CurrentVersionRun_8d1e {
  strings:
    $key_8d1e = { de 71 [2] fa 7f [2] d1 53 [2] ff 71 [2] eb 6a [2] e4 70 [2] fa 6d [2] f8 6c [2] e3 6a [2] ff 6d [2] e3 42 }

  condition:
    any of them
}