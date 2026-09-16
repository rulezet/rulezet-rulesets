rule TTP_XOR_QUAD_CurrentVersionRun_8dc2 {
  strings:
    $key_8dc2 = { de ad [2] fa a3 [2] d1 8f [2] ff ad [2] eb b6 [2] e4 ac [2] fa b1 [2] f8 b0 [2] e3 b6 [2] ff b1 [2] e3 9e }

  condition:
    any of them
}