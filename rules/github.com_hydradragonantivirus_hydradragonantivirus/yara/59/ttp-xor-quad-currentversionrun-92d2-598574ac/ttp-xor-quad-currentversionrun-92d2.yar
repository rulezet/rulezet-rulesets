rule TTP_XOR_QUAD_CurrentVersionRun_92d2 {
  strings:
    $key_92d2 = { c1 bd [2] e5 b3 [2] ce 9f [2] e0 bd [2] f4 a6 [2] fb bc [2] e5 a1 [2] e7 a0 [2] fc a6 [2] e0 a1 [2] fc 8e }

  condition:
    any of them
}