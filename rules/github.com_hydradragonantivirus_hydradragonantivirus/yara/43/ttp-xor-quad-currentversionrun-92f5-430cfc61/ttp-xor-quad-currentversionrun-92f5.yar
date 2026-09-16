rule TTP_XOR_QUAD_CurrentVersionRun_92f5 {
  strings:
    $key_92f5 = { c1 9a [2] e5 94 [2] ce b8 [2] e0 9a [2] f4 81 [2] fb 9b [2] e5 86 [2] e7 87 [2] fc 81 [2] e0 86 [2] fc a9 }

  condition:
    any of them
}