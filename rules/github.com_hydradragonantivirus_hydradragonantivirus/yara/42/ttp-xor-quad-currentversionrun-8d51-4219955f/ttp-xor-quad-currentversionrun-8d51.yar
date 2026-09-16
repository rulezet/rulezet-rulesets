rule TTP_XOR_QUAD_CurrentVersionRun_8d51 {
  strings:
    $key_8d51 = { de 3e [2] fa 30 [2] d1 1c [2] ff 3e [2] eb 25 [2] e4 3f [2] fa 22 [2] f8 23 [2] e3 25 [2] ff 22 [2] e3 0d }

  condition:
    any of them
}