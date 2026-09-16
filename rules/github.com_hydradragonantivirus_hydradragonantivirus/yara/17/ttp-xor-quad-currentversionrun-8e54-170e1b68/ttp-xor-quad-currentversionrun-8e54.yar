rule TTP_XOR_QUAD_CurrentVersionRun_8e54 {
  strings:
    $key_8e54 = { dd 3b [2] f9 35 [2] d2 19 [2] fc 3b [2] e8 20 [2] e7 3a [2] f9 27 [2] fb 26 [2] e0 20 [2] fc 27 [2] e0 08 }

  condition:
    any of them
}