rule TTP_XOR_QUAD_CurrentVersionRun_8d71 {
  strings:
    $key_8d71 = { de 1e [2] fa 10 [2] d1 3c [2] ff 1e [2] eb 05 [2] e4 1f [2] fa 02 [2] f8 03 [2] e3 05 [2] ff 02 [2] e3 2d }

  condition:
    any of them
}