rule TTP_XOR_QUAD_CurrentVersionRun_8db4 {
  strings:
    $key_8db4 = { de db [2] fa d5 [2] d1 f9 [2] ff db [2] eb c0 [2] e4 da [2] fa c7 [2] f8 c6 [2] e3 c0 [2] ff c7 [2] e3 e8 }

  condition:
    any of them
}