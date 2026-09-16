rule TTP_XOR_QUAD_CurrentVersionRun_8df0 {
  strings:
    $key_8df0 = { de 9f [2] fa 91 [2] d1 bd [2] ff 9f [2] eb 84 [2] e4 9e [2] fa 83 [2] f8 82 [2] e3 84 [2] ff 83 [2] e3 ac }

  condition:
    any of them
}