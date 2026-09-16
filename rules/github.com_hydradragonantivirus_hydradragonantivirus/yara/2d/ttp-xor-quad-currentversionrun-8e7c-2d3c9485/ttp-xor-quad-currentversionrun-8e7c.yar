rule TTP_XOR_QUAD_CurrentVersionRun_8e7c {
  strings:
    $key_8e7c = { dd 13 [2] f9 1d [2] d2 31 [2] fc 13 [2] e8 08 [2] e7 12 [2] f9 0f [2] fb 0e [2] e0 08 [2] fc 0f [2] e0 20 }

  condition:
    any of them
}