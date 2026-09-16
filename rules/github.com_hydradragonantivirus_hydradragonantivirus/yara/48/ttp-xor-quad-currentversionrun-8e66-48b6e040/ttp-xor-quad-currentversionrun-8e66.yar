rule TTP_XOR_QUAD_CurrentVersionRun_8e66 {
  strings:
    $key_8e66 = { dd 09 [2] f9 07 [2] d2 2b [2] fc 09 [2] e8 12 [2] e7 08 [2] f9 15 [2] fb 14 [2] e0 12 [2] fc 15 [2] e0 3a }

  condition:
    any of them
}