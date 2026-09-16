rule TTP_XOR_QUAD_CurrentVersionRun_8e72 {
  strings:
    $key_8e72 = { dd 1d [2] f9 13 [2] d2 3f [2] fc 1d [2] e8 06 [2] e7 1c [2] f9 01 [2] fb 00 [2] e0 06 [2] fc 01 [2] e0 2e }

  condition:
    any of them
}