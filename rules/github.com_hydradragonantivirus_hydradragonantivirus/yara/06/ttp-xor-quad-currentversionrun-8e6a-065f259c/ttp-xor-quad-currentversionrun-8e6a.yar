rule TTP_XOR_QUAD_CurrentVersionRun_8e6a {
  strings:
    $key_8e6a = { dd 05 [2] f9 0b [2] d2 27 [2] fc 05 [2] e8 1e [2] e7 04 [2] f9 19 [2] fb 18 [2] e0 1e [2] fc 19 [2] e0 36 }

  condition:
    any of them
}