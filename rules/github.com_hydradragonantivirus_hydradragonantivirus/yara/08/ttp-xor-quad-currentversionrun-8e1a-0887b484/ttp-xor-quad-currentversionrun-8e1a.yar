rule TTP_XOR_QUAD_CurrentVersionRun_8e1a {
  strings:
    $key_8e1a = { dd 75 [2] f9 7b [2] d2 57 [2] fc 75 [2] e8 6e [2] e7 74 [2] f9 69 [2] fb 68 [2] e0 6e [2] fc 69 [2] e0 46 }

  condition:
    any of them
}