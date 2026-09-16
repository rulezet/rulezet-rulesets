rule TTP_XOR_QUAD_CurrentVersionRun_8e65 {
  strings:
    $key_8e65 = { dd 0a [2] f9 04 [2] d2 28 [2] fc 0a [2] e8 11 [2] e7 0b [2] f9 16 [2] fb 17 [2] e0 11 [2] fc 16 [2] e0 39 }

  condition:
    any of them
}