rule TTP_XOR_QUAD_CurrentVersionRun_8e18 {
  strings:
    $key_8e18 = { dd 77 [2] f9 79 [2] d2 55 [2] fc 77 [2] e8 6c [2] e7 76 [2] f9 6b [2] fb 6a [2] e0 6c [2] fc 6b [2] e0 44 }

  condition:
    any of them
}