rule TTP_XOR_QUAD_CurrentVersionRun_8e2a {
  strings:
    $key_8e2a = { dd 45 [2] f9 4b [2] d2 67 [2] fc 45 [2] e8 5e [2] e7 44 [2] f9 59 [2] fb 58 [2] e0 5e [2] fc 59 [2] e0 76 }

  condition:
    any of them
}