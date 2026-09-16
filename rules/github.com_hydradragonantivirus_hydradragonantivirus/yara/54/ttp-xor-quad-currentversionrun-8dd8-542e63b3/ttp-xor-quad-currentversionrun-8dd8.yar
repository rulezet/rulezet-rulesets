rule TTP_XOR_QUAD_CurrentVersionRun_8dd8 {
  strings:
    $key_8dd8 = { de b7 [2] fa b9 [2] d1 95 [2] ff b7 [2] eb ac [2] e4 b6 [2] fa ab [2] f8 aa [2] e3 ac [2] ff ab [2] e3 84 }

  condition:
    any of them
}