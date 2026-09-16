rule TTP_XOR_QUAD_CurrentVersionRun_8d01 {
  strings:
    $key_8d01 = { de 6e [2] fa 60 [2] d1 4c [2] ff 6e [2] eb 75 [2] e4 6f [2] fa 72 [2] f8 73 [2] e3 75 [2] ff 72 [2] e3 5d }

  condition:
    any of them
}