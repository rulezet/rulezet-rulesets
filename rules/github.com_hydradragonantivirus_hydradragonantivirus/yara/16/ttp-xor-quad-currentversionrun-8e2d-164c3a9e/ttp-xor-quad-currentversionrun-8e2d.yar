rule TTP_XOR_QUAD_CurrentVersionRun_8e2d {
  strings:
    $key_8e2d = { dd 42 [2] f9 4c [2] d2 60 [2] fc 42 [2] e8 59 [2] e7 43 [2] f9 5e [2] fb 5f [2] e0 59 [2] fc 5e [2] e0 71 }

  condition:
    any of them
}