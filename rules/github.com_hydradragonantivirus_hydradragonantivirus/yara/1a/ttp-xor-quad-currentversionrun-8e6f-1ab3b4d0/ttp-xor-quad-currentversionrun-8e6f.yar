rule TTP_XOR_QUAD_CurrentVersionRun_8e6f {
  strings:
    $key_8e6f = { dd 00 [2] f9 0e [2] d2 22 [2] fc 00 [2] e8 1b [2] e7 01 [2] f9 1c [2] fb 1d [2] e0 1b [2] fc 1c [2] e0 33 }

  condition:
    any of them
}