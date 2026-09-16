rule TTP_XOR_QUAD_CurrentVersionRun_8ef9 {
  strings:
    $key_8ef9 = { dd 96 [2] f9 98 [2] d2 b4 [2] fc 96 [2] e8 8d [2] e7 97 [2] f9 8a [2] fb 8b [2] e0 8d [2] fc 8a [2] e0 a5 }

  condition:
    any of them
}