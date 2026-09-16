rule TTP_XOR_QUAD_CurrentVersionRun_8e19 {
  strings:
    $key_8e19 = { dd 76 [2] f9 78 [2] d2 54 [2] fc 76 [2] e8 6d [2] e7 77 [2] f9 6a [2] fb 6b [2] e0 6d [2] fc 6a [2] e0 45 }

  condition:
    any of them
}