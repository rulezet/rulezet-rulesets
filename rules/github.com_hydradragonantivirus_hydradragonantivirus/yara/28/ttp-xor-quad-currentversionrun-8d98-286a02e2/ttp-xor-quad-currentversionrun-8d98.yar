rule TTP_XOR_QUAD_CurrentVersionRun_8d98 {
  strings:
    $key_8d98 = { de f7 [2] fa f9 [2] d1 d5 [2] ff f7 [2] eb ec [2] e4 f6 [2] fa eb [2] f8 ea [2] e3 ec [2] ff eb [2] e3 c4 }

  condition:
    any of them
}