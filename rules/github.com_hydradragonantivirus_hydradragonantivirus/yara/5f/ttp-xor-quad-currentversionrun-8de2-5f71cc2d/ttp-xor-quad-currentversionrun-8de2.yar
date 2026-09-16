rule TTP_XOR_QUAD_CurrentVersionRun_8de2 {
  strings:
    $key_8de2 = { de 8d [2] fa 83 [2] d1 af [2] ff 8d [2] eb 96 [2] e4 8c [2] fa 91 [2] f8 90 [2] e3 96 [2] ff 91 [2] e3 be }

  condition:
    any of them
}