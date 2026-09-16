rule TTP_XOR_QUAD_CurrentVersionRun_92c0 {
  strings:
    $key_92c0 = { c1 af [2] e5 a1 [2] ce 8d [2] e0 af [2] f4 b4 [2] fb ae [2] e5 b3 [2] e7 b2 [2] fc b4 [2] e0 b3 [2] fc 9c }

  condition:
    any of them
}