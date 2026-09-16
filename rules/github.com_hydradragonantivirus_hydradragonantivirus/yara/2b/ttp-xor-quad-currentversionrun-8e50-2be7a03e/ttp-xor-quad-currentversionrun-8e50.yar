rule TTP_XOR_QUAD_CurrentVersionRun_8e50 {
  strings:
    $key_8e50 = { dd 3f [2] f9 31 [2] d2 1d [2] fc 3f [2] e8 24 [2] e7 3e [2] f9 23 [2] fb 22 [2] e0 24 [2] fc 23 [2] e0 0c }

  condition:
    any of them
}