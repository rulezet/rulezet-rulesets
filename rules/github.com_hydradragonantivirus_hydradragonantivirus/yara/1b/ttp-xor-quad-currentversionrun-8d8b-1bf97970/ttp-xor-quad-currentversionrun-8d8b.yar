rule TTP_XOR_QUAD_CurrentVersionRun_8d8b {
  strings:
    $key_8d8b = { de e4 [2] fa ea [2] d1 c6 [2] ff e4 [2] eb ff [2] e4 e5 [2] fa f8 [2] f8 f9 [2] e3 ff [2] ff f8 [2] e3 d7 }

  condition:
    any of them
}