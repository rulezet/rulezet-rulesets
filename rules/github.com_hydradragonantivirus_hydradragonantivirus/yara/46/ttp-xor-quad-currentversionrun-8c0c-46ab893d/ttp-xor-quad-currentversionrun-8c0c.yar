rule TTP_XOR_QUAD_CurrentVersionRun_8c0c {
  strings:
    $key_8c0c = { df 63 [2] fb 6d [2] d0 41 [2] fe 63 [2] ea 78 [2] e5 62 [2] fb 7f [2] f9 7e [2] e2 78 [2] fe 7f [2] e2 50 }

  condition:
    any of them
}