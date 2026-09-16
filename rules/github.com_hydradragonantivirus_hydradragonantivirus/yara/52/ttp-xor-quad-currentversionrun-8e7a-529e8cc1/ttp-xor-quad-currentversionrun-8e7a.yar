rule TTP_XOR_QUAD_CurrentVersionRun_8e7a {
  strings:
    $key_8e7a = { dd 15 [2] f9 1b [2] d2 37 [2] fc 15 [2] e8 0e [2] e7 14 [2] f9 09 [2] fb 08 [2] e0 0e [2] fc 09 [2] e0 26 }

  condition:
    any of them
}