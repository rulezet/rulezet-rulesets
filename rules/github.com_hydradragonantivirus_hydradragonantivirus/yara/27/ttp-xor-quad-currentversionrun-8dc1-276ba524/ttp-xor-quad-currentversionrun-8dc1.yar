rule TTP_XOR_QUAD_CurrentVersionRun_8dc1 {
  strings:
    $key_8dc1 = { de ae [2] fa a0 [2] d1 8c [2] ff ae [2] eb b5 [2] e4 af [2] fa b2 [2] f8 b3 [2] e3 b5 [2] ff b2 [2] e3 9d }

  condition:
    any of them
}