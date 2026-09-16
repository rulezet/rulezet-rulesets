rule TTP_XOR_QUAD_CurrentVersionRun_8d2f {
  strings:
    $key_8d2f = { de 40 [2] fa 4e [2] d1 62 [2] ff 40 [2] eb 5b [2] e4 41 [2] fa 5c [2] f8 5d [2] e3 5b [2] ff 5c [2] e3 73 }

  condition:
    any of them
}