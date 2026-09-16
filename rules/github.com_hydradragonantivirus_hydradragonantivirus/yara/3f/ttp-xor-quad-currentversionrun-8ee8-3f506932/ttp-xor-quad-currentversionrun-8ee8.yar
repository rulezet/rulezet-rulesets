rule TTP_XOR_QUAD_CurrentVersionRun_8ee8 {
  strings:
    $key_8ee8 = { dd 87 [2] f9 89 [2] d2 a5 [2] fc 87 [2] e8 9c [2] e7 86 [2] f9 9b [2] fb 9a [2] e0 9c [2] fc 9b [2] e0 b4 }

  condition:
    any of them
}