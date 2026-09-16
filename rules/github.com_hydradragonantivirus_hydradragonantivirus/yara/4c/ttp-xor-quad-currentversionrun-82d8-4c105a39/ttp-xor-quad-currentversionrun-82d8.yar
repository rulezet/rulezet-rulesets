rule TTP_XOR_QUAD_CurrentVersionRun_82d8 {
  strings:
    $key_82d8 = { d1 b7 [2] f5 b9 [2] de 95 [2] f0 b7 [2] e4 ac [2] eb b6 [2] f5 ab [2] f7 aa [2] ec ac [2] f0 ab [2] ec 84 }

  condition:
    any of them
}