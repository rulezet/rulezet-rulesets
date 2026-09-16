rule TTP_XOR_QUAD_CurrentVersionRun_8cef {
  strings:
    $key_8cef = { df 80 [2] fb 8e [2] d0 a2 [2] fe 80 [2] ea 9b [2] e5 81 [2] fb 9c [2] f9 9d [2] e2 9b [2] fe 9c [2] e2 b3 }

  condition:
    any of them
}