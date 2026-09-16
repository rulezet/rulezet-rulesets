rule TTP_XOR_QUAD_CurrentVersionRun_951f {
  strings:
    $key_951f = { c6 70 [2] e2 7e [2] c9 52 [2] e7 70 [2] f3 6b [2] fc 71 [2] e2 6c [2] e0 6d [2] fb 6b [2] e7 6c [2] fb 43 }

  condition:
    any of them
}