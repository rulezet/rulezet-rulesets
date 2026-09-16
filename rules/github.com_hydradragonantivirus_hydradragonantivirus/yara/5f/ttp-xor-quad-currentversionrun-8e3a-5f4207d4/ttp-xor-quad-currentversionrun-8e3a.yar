rule TTP_XOR_QUAD_CurrentVersionRun_8e3a {
  strings:
    $key_8e3a = { dd 55 [2] f9 5b [2] d2 77 [2] fc 55 [2] e8 4e [2] e7 54 [2] f9 49 [2] fb 48 [2] e0 4e [2] fc 49 [2] e0 66 }

  condition:
    any of them
}