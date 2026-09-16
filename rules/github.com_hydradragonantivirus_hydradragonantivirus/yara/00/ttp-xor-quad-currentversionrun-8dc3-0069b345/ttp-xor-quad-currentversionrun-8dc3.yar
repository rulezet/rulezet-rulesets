rule TTP_XOR_QUAD_CurrentVersionRun_8dc3 {
  strings:
    $key_8dc3 = { de ac [2] fa a2 [2] d1 8e [2] ff ac [2] eb b7 [2] e4 ad [2] fa b0 [2] f8 b1 [2] e3 b7 [2] ff b0 [2] e3 9f }

  condition:
    any of them
}