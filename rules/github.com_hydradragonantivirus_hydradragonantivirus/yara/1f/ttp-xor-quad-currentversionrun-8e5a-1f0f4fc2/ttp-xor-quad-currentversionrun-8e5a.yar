rule TTP_XOR_QUAD_CurrentVersionRun_8e5a {
  strings:
    $key_8e5a = { dd 35 [2] f9 3b [2] d2 17 [2] fc 35 [2] e8 2e [2] e7 34 [2] f9 29 [2] fb 28 [2] e0 2e [2] fc 29 [2] e0 06 }

  condition:
    any of them
}