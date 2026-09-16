rule TTP_XOR_QUAD_CurrentVersionRun_95d8 {
  strings:
    $key_95d8 = { c6 b7 [2] e2 b9 [2] c9 95 [2] e7 b7 [2] f3 ac [2] fc b6 [2] e2 ab [2] e0 aa [2] fb ac [2] e7 ab [2] fb 84 }

  condition:
    any of them
}