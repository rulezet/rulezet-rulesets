rule TTP_XOR_QUAD_CurrentVersionRun_92e8 {
  strings:
    $key_92e8 = { c1 87 [2] e5 89 [2] ce a5 [2] e0 87 [2] f4 9c [2] fb 86 [2] e5 9b [2] e7 9a [2] fc 9c [2] e0 9b [2] fc b4 }

  condition:
    any of them
}