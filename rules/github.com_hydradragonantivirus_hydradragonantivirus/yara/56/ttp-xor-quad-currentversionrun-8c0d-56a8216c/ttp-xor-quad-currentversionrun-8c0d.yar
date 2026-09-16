rule TTP_XOR_QUAD_CurrentVersionRun_8c0d {
  strings:
    $key_8c0d = { df 62 [2] fb 6c [2] d0 40 [2] fe 62 [2] ea 79 [2] e5 63 [2] fb 7e [2] f9 7f [2] e2 79 [2] fe 7e [2] e2 51 }

  condition:
    any of them
}