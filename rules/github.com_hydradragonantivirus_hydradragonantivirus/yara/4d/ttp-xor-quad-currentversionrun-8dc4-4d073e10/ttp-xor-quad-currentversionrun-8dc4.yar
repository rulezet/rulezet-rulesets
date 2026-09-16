rule TTP_XOR_QUAD_CurrentVersionRun_8dc4 {
  strings:
    $key_8dc4 = { de ab [2] fa a5 [2] d1 89 [2] ff ab [2] eb b0 [2] e4 aa [2] fa b7 [2] f8 b6 [2] e3 b0 [2] ff b7 [2] e3 98 }

  condition:
    any of them
}