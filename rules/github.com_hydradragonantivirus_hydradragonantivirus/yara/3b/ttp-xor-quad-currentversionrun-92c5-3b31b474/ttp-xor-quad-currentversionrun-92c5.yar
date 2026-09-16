rule TTP_XOR_QUAD_CurrentVersionRun_92c5 {
  strings:
    $key_92c5 = { c1 aa [2] e5 a4 [2] ce 88 [2] e0 aa [2] f4 b1 [2] fb ab [2] e5 b6 [2] e7 b7 [2] fc b1 [2] e0 b6 [2] fc 99 }

  condition:
    any of them
}