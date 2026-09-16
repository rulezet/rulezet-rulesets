rule TTP_XOR_QUAD_CurrentVersionRun_92c7 {
  strings:
    $key_92c7 = { c1 a8 [2] e5 a6 [2] ce 8a [2] e0 a8 [2] f4 b3 [2] fb a9 [2] e5 b4 [2] e7 b5 [2] fc b3 [2] e0 b4 [2] fc 9b }

  condition:
    any of them
}