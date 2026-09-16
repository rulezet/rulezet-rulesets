rule TTP_XOR_QUAD_CurrentVersionRun_8e7d {
  strings:
    $key_8e7d = { dd 12 [2] f9 1c [2] d2 30 [2] fc 12 [2] e8 09 [2] e7 13 [2] f9 0e [2] fb 0f [2] e0 09 [2] fc 0e [2] e0 21 }

  condition:
    any of them
}