rule TTP_XOR_QUAD_CurrentVersionRun_8e5c {
  strings:
    $key_8e5c = { dd 33 [2] f9 3d [2] d2 11 [2] fc 33 [2] e8 28 [2] e7 32 [2] f9 2f [2] fb 2e [2] e0 28 [2] fc 2f [2] e0 00 }

  condition:
    any of them
}