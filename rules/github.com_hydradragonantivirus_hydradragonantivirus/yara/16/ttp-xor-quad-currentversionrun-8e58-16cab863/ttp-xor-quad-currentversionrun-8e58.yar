rule TTP_XOR_QUAD_CurrentVersionRun_8e58 {
  strings:
    $key_8e58 = { dd 37 [2] f9 39 [2] d2 15 [2] fc 37 [2] e8 2c [2] e7 36 [2] f9 2b [2] fb 2a [2] e0 2c [2] fc 2b [2] e0 04 }

  condition:
    any of them
}