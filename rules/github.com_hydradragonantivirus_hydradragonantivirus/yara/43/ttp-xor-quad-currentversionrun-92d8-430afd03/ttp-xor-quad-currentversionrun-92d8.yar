rule TTP_XOR_QUAD_CurrentVersionRun_92d8 {
  strings:
    $key_92d8 = { c1 b7 [2] e5 b9 [2] ce 95 [2] e0 b7 [2] f4 ac [2] fb b6 [2] e5 ab [2] e7 aa [2] fc ac [2] e0 ab [2] fc 84 }

  condition:
    any of them
}