rule TTP_XOR_QUAD_CurrentVersionRun_8e46 {
  strings:
    $key_8e46 = { dd 29 [2] f9 27 [2] d2 0b [2] fc 29 [2] e8 32 [2] e7 28 [2] f9 35 [2] fb 34 [2] e0 32 [2] fc 35 [2] e0 1a }

  condition:
    any of them
}