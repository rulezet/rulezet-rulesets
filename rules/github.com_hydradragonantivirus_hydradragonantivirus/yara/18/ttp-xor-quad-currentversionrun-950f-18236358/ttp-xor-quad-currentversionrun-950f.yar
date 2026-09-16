rule TTP_XOR_QUAD_CurrentVersionRun_950f {
  strings:
    $key_950f = { c6 60 [2] e2 6e [2] c9 42 [2] e7 60 [2] f3 7b [2] fc 61 [2] e2 7c [2] e0 7d [2] fb 7b [2] e7 7c [2] fb 53 }

  condition:
    any of them
}