rule TTP_XOR_QUAD_CurrentVersionRun_bc8e {
  strings:
    $key_bc8e = { ef e1 [2] cb ef [2] e0 c3 [2] ce e1 [2] da fa [2] d5 e0 [2] cb fd [2] c9 fc [2] d2 fa [2] ce fd [2] d2 d2 }

  condition:
    any of them
}