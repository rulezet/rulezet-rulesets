rule TTP_XOR_QUAD_CurrentVersionRun_8e17 {
  strings:
    $key_8e17 = { dd 78 [2] f9 76 [2] d2 5a [2] fc 78 [2] e8 63 [2] e7 79 [2] f9 64 [2] fb 65 [2] e0 63 [2] fc 64 [2] e0 4b }

  condition:
    any of them
}