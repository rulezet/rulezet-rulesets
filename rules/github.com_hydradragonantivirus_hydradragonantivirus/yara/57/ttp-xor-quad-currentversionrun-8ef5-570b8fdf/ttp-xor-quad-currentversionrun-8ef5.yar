rule TTP_XOR_QUAD_CurrentVersionRun_8ef5 {
  strings:
    $key_8ef5 = { dd 9a [2] f9 94 [2] d2 b8 [2] fc 9a [2] e8 81 [2] e7 9b [2] f9 86 [2] fb 87 [2] e0 81 [2] fc 86 [2] e0 a9 }

  condition:
    any of them
}