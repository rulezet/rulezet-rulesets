rule TTP_XOR_QUAD_CurrentVersionRun_953f {
  strings:
    $key_953f = { c6 50 [2] e2 5e [2] c9 72 [2] e7 50 [2] f3 4b [2] fc 51 [2] e2 4c [2] e0 4d [2] fb 4b [2] e7 4c [2] fb 63 }

  condition:
    any of them
}