rule TTP_XOR_QUAD_CurrentVersionRun_92c4 {
  strings:
    $key_92c4 = { c1 ab [2] e5 a5 [2] ce 89 [2] e0 ab [2] f4 b0 [2] fb aa [2] e5 b7 [2] e7 b6 [2] fc b0 [2] e0 b7 [2] fc 98 }

  condition:
    any of them
}