rule TTP_XOR_QUAD_CurrentVersionRun_92d9 {
  strings:
    $key_92d9 = { c1 b6 [2] e5 b8 [2] ce 94 [2] e0 b6 [2] f4 ad [2] fb b7 [2] e5 aa [2] e7 ab [2] fc ad [2] e0 aa [2] fc 85 }

  condition:
    any of them
}