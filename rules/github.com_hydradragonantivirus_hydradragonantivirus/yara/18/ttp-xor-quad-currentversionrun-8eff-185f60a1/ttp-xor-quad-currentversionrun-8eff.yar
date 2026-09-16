rule TTP_XOR_QUAD_CurrentVersionRun_8eff {
  strings:
    $key_8eff = { dd 90 [2] f9 9e [2] d2 b2 [2] fc 90 [2] e8 8b [2] e7 91 [2] f9 8c [2] fb 8d [2] e0 8b [2] fc 8c [2] e0 a3 }

  condition:
    any of them
}