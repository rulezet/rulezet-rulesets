rule TTP_XOR_QUAD_CurrentVersionRun_8dc5 {
  strings:
    $key_8dc5 = { de aa [2] fa a4 [2] d1 88 [2] ff aa [2] eb b1 [2] e4 ab [2] fa b6 [2] f8 b7 [2] e3 b1 [2] ff b6 [2] e3 99 }

  condition:
    any of them
}