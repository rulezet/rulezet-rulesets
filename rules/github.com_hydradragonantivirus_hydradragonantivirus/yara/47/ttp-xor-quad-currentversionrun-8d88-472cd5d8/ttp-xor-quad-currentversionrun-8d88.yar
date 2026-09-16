rule TTP_XOR_QUAD_CurrentVersionRun_8d88 {
  strings:
    $key_8d88 = { de e7 [2] fa e9 [2] d1 c5 [2] ff e7 [2] eb fc [2] e4 e6 [2] fa fb [2] f8 fa [2] e3 fc [2] ff fb [2] e3 d4 }

  condition:
    any of them
}