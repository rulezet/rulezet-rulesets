rule TTP_XOR_QUAD_CurrentVersionRun_8e1b {
  strings:
    $key_8e1b = { dd 74 [2] f9 7a [2] d2 56 [2] fc 74 [2] e8 6f [2] e7 75 [2] f9 68 [2] fb 69 [2] e0 6f [2] fc 68 [2] e0 47 }

  condition:
    any of them
}