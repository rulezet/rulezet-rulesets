rule TTP_XOR_QUAD_CurrentVersionRun_922b {
  strings:
    $key_922b = { c1 44 [2] e5 4a [2] ce 66 [2] e0 44 [2] f4 5f [2] fb 45 [2] e5 58 [2] e7 59 [2] fc 5f [2] e0 58 [2] fc 77 }

  condition:
    any of them
}