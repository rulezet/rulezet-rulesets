rule TTP_XOR_QUAD_CurrentVersionRun_8dad {
  strings:
    $key_8dad = { de c2 [2] fa cc [2] d1 e0 [2] ff c2 [2] eb d9 [2] e4 c3 [2] fa de [2] f8 df [2] e3 d9 [2] ff de [2] e3 f1 }

  condition:
    any of them
}