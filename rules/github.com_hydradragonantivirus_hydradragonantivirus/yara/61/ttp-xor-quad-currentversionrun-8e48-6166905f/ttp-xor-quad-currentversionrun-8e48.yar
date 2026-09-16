rule TTP_XOR_QUAD_CurrentVersionRun_8e48 {
  strings:
    $key_8e48 = { dd 27 [2] f9 29 [2] d2 05 [2] fc 27 [2] e8 3c [2] e7 26 [2] f9 3b [2] fb 3a [2] e0 3c [2] fc 3b [2] e0 14 }

  condition:
    any of them
}