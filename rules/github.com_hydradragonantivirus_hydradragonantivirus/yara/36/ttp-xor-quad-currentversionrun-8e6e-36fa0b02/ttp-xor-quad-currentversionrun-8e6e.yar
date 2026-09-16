rule TTP_XOR_QUAD_CurrentVersionRun_8e6e {
  strings:
    $key_8e6e = { dd 01 [2] f9 0f [2] d2 23 [2] fc 01 [2] e8 1a [2] e7 00 [2] f9 1d [2] fb 1c [2] e0 1a [2] fc 1d [2] e0 32 }

  condition:
    any of them
}