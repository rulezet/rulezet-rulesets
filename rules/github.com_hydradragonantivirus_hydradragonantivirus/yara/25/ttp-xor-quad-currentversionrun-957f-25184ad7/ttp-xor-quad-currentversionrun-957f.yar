rule TTP_XOR_QUAD_CurrentVersionRun_957f {
  strings:
    $key_957f = { c6 10 [2] e2 1e [2] c9 32 [2] e7 10 [2] f3 0b [2] fc 11 [2] e2 0c [2] e0 0d [2] fb 0b [2] e7 0c [2] fb 23 }

  condition:
    any of them
}