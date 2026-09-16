rule TTP_XOR_QUAD_CurrentVersionRun_8de1 {
  strings:
    $key_8de1 = { de 8e [2] fa 80 [2] d1 ac [2] ff 8e [2] eb 95 [2] e4 8f [2] fa 92 [2] f8 93 [2] e3 95 [2] ff 92 [2] e3 bd }

  condition:
    any of them
}