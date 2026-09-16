rule TTP_XOR_QUAD_CurrentVersionRun_8ef8 {
  strings:
    $key_8ef8 = { dd 97 [2] f9 99 [2] d2 b5 [2] fc 97 [2] e8 8c [2] e7 96 [2] f9 8b [2] fb 8a [2] e0 8c [2] fc 8b [2] e0 a4 }

  condition:
    any of them
}