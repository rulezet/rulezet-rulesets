rule TTP_XOR_QUAD_CurrentVersionRun_92e4 {
  strings:
    $key_92e4 = { c1 8b [2] e5 85 [2] ce a9 [2] e0 8b [2] f4 90 [2] fb 8a [2] e5 97 [2] e7 96 [2] fc 90 [2] e0 97 [2] fc b8 }

  condition:
    any of them
}