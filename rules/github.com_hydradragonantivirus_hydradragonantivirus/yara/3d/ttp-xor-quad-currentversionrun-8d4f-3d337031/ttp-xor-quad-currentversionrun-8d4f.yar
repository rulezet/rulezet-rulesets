rule TTP_XOR_QUAD_CurrentVersionRun_8d4f {
  strings:
    $key_8d4f = { de 20 [2] fa 2e [2] d1 02 [2] ff 20 [2] eb 3b [2] e4 21 [2] fa 3c [2] f8 3d [2] e3 3b [2] ff 3c [2] e3 13 }

  condition:
    any of them
}