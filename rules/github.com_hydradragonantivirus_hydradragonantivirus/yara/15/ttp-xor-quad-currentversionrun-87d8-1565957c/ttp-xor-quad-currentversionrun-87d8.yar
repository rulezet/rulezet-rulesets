rule TTP_XOR_QUAD_CurrentVersionRun_87d8 {
  strings:
    $key_87d8 = { d4 b7 [2] f0 b9 [2] db 95 [2] f5 b7 [2] e1 ac [2] ee b6 [2] f0 ab [2] f2 aa [2] e9 ac [2] f5 ab [2] e9 84 }

  condition:
    any of them
}