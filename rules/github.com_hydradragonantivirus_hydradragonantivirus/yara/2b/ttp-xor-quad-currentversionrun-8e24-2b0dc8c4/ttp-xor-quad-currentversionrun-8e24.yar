rule TTP_XOR_QUAD_CurrentVersionRun_8e24 {
  strings:
    $key_8e24 = { dd 4b [2] f9 45 [2] d2 69 [2] fc 4b [2] e8 50 [2] e7 4a [2] f9 57 [2] fb 56 [2] e0 50 [2] fc 57 [2] e0 78 }

  condition:
    any of them
}