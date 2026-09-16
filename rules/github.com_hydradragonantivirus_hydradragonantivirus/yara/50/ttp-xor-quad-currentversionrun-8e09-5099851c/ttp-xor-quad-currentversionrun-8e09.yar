rule TTP_XOR_QUAD_CurrentVersionRun_8e09 {
  strings:
    $key_8e09 = { dd 66 [2] f9 68 [2] d2 44 [2] fc 66 [2] e8 7d [2] e7 67 [2] f9 7a [2] fb 7b [2] e0 7d [2] fc 7a [2] e0 55 }

  condition:
    any of them
}