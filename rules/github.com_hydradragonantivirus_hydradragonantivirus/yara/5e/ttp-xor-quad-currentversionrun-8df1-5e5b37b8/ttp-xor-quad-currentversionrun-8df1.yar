rule TTP_XOR_QUAD_CurrentVersionRun_8df1 {
  strings:
    $key_8df1 = { de 9e [2] fa 90 [2] d1 bc [2] ff 9e [2] eb 85 [2] e4 9f [2] fa 82 [2] f8 83 [2] e3 85 [2] ff 82 [2] e3 ad }

  condition:
    any of them
}