rule TTP_XOR_QUAD_CurrentVersionRun_8e5d {
  strings:
    $key_8e5d = { dd 32 [2] f9 3c [2] d2 10 [2] fc 32 [2] e8 29 [2] e7 33 [2] f9 2e [2] fb 2f [2] e0 29 [2] fc 2e [2] e0 01 }

  condition:
    any of them
}