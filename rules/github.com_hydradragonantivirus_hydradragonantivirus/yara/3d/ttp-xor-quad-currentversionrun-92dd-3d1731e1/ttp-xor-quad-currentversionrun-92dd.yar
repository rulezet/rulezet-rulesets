rule TTP_XOR_QUAD_CurrentVersionRun_92dd {
  strings:
    $key_92dd = { c1 b2 [2] e5 bc [2] ce 90 [2] e0 b2 [2] f4 a9 [2] fb b3 [2] e5 ae [2] e7 af [2] fc a9 [2] e0 ae [2] fc 81 }

  condition:
    any of them
}