rule TTP_XOR_QUAD_CurrentVersionRun_8d62 {
  strings:
    $key_8d62 = { de 0d [2] fa 03 [2] d1 2f [2] ff 0d [2] eb 16 [2] e4 0c [2] fa 11 [2] f8 10 [2] e3 16 [2] ff 11 [2] e3 3e }

  condition:
    any of them
}