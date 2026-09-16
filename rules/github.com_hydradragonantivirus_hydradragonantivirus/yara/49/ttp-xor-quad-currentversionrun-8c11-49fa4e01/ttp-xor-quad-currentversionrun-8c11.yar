rule TTP_XOR_QUAD_CurrentVersionRun_8c11 {
  strings:
    $key_8c11 = { df 7e [2] fb 70 [2] d0 5c [2] fe 7e [2] ea 65 [2] e5 7f [2] fb 62 [2] f9 63 [2] e2 65 [2] fe 62 [2] e2 4d }

  condition:
    any of them
}