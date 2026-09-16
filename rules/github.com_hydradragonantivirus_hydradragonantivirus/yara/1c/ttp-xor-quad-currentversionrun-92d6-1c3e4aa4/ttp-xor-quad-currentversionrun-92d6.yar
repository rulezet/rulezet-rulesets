rule TTP_XOR_QUAD_CurrentVersionRun_92d6 {
  strings:
    $key_92d6 = { c1 b9 [2] e5 b7 [2] ce 9b [2] e0 b9 [2] f4 a2 [2] fb b8 [2] e5 a5 [2] e7 a4 [2] fc a2 [2] e0 a5 [2] fc 8a }

  condition:
    any of them
}