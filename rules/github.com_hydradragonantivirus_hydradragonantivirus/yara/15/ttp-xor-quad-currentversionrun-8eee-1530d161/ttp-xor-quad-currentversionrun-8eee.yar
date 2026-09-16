rule TTP_XOR_QUAD_CurrentVersionRun_8eee {
  strings:
    $key_8eee = { dd 81 [2] f9 8f [2] d2 a3 [2] fc 81 [2] e8 9a [2] e7 80 [2] f9 9d [2] fb 9c [2] e0 9a [2] fc 9d [2] e0 b2 }

  condition:
    any of them
}