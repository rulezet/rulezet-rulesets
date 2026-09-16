rule TTP_XOR_QUAD_CurrentVersionRun_8e6b {
  strings:
    $key_8e6b = { dd 04 [2] f9 0a [2] d2 26 [2] fc 04 [2] e8 1f [2] e7 05 [2] f9 18 [2] fb 19 [2] e0 1f [2] fc 18 [2] e0 37 }

  condition:
    any of them
}