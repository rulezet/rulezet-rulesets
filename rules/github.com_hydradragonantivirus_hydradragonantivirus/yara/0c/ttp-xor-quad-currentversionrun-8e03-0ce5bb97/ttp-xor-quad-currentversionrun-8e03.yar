rule TTP_XOR_QUAD_CurrentVersionRun_8e03 {
  strings:
    $key_8e03 = { dd 6c [2] f9 62 [2] d2 4e [2] fc 6c [2] e8 77 [2] e7 6d [2] f9 70 [2] fb 71 [2] e0 77 [2] fc 70 [2] e0 5f }

  condition:
    any of them
}