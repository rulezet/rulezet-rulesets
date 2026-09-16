rule TTP_XOR_QUAD_CurrentVersionRun_8e4a {
  strings:
    $key_8e4a = { dd 25 [2] f9 2b [2] d2 07 [2] fc 25 [2] e8 3e [2] e7 24 [2] f9 39 [2] fb 38 [2] e0 3e [2] fc 39 [2] e0 16 }

  condition:
    any of them
}