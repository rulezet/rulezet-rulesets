rule TTP_XOR_QUAD_CurrentVersionRun_8d03 {
  strings:
    $key_8d03 = { de 6c [2] fa 62 [2] d1 4e [2] ff 6c [2] eb 77 [2] e4 6d [2] fa 70 [2] f8 71 [2] e3 77 [2] ff 70 [2] e3 5f }

  condition:
    any of them
}