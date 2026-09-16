rule TTP_XOR_QUAD_CurrentVersionRun_8c10 {
  strings:
    $key_8c10 = { df 7f [2] fb 71 [2] d0 5d [2] fe 7f [2] ea 64 [2] e5 7e [2] fb 63 [2] f9 62 [2] e2 64 [2] fe 63 [2] e2 4c }

  condition:
    any of them
}