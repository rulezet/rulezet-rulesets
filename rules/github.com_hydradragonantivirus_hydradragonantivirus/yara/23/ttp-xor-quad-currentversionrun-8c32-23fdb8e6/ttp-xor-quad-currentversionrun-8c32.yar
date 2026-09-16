rule TTP_XOR_QUAD_CurrentVersionRun_8c32 {
  strings:
    $key_8c32 = { df 5d [2] fb 53 [2] d0 7f [2] fe 5d [2] ea 46 [2] e5 5c [2] fb 41 [2] f9 40 [2] e2 46 [2] fe 41 [2] e2 6e }

  condition:
    any of them
}