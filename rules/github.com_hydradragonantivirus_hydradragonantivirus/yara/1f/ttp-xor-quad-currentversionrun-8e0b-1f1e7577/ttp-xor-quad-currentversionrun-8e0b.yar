rule TTP_XOR_QUAD_CurrentVersionRun_8e0b {
  strings:
    $key_8e0b = { dd 64 [2] f9 6a [2] d2 46 [2] fc 64 [2] e8 7f [2] e7 65 [2] f9 78 [2] fb 79 [2] e0 7f [2] fc 78 [2] e0 57 }

  condition:
    any of them
}