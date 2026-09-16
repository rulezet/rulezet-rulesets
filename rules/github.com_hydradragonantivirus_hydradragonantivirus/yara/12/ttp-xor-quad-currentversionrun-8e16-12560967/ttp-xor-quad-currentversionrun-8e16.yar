rule TTP_XOR_QUAD_CurrentVersionRun_8e16 {
  strings:
    $key_8e16 = { dd 79 [2] f9 77 [2] d2 5b [2] fc 79 [2] e8 62 [2] e7 78 [2] f9 65 [2] fb 64 [2] e0 62 [2] fc 65 [2] e0 4a }

  condition:
    any of them
}