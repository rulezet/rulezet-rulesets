rule TTP_XOR_QUAD_CurrentVersionRun_952d {
  strings:
    $key_952d = { c6 42 [2] e2 4c [2] c9 60 [2] e7 42 [2] f3 59 [2] fc 43 [2] e2 5e [2] e0 5f [2] fb 59 [2] e7 5e [2] fb 71 }

  condition:
    any of them
}