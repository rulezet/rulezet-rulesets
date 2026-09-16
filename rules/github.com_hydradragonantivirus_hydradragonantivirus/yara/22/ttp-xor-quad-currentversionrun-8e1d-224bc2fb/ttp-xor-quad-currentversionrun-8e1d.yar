rule TTP_XOR_QUAD_CurrentVersionRun_8e1d {
  strings:
    $key_8e1d = { dd 72 [2] f9 7c [2] d2 50 [2] fc 72 [2] e8 69 [2] e7 73 [2] f9 6e [2] fb 6f [2] e0 69 [2] fc 6e [2] e0 41 }

  condition:
    any of them
}