rule TTP_XOR_QUAD_CurrentVersionRun_952f {
  strings:
    $key_952f = { c6 40 [2] e2 4e [2] c9 62 [2] e7 40 [2] f3 5b [2] fc 41 [2] e2 5c [2] e0 5d [2] fb 5b [2] e7 5c [2] fb 73 }

  condition:
    any of them
}