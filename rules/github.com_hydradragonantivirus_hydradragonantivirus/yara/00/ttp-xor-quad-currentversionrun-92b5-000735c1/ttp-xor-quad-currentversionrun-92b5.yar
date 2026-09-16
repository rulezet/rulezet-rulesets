rule TTP_XOR_QUAD_CurrentVersionRun_92b5 {
  strings:
    $key_92b5 = { c1 da [2] e5 d4 [2] ce f8 [2] e0 da [2] f4 c1 [2] fb db [2] e5 c6 [2] e7 c7 [2] fc c1 [2] e0 c6 [2] fc e9 }

  condition:
    any of them
}