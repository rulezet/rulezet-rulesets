rule TTP_XOR_QUAD_CurrentVersionRun_8d8a {
  strings:
    $key_8d8a = { de e5 [2] fa eb [2] d1 c7 [2] ff e5 [2] eb fe [2] e4 e4 [2] fa f9 [2] f8 f8 [2] e3 fe [2] ff f9 [2] e3 d6 }

  condition:
    any of them
}