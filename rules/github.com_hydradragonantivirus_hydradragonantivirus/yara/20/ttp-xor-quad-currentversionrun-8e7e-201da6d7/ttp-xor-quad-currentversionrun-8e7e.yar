rule TTP_XOR_QUAD_CurrentVersionRun_8e7e {
  strings:
    $key_8e7e = { dd 11 [2] f9 1f [2] d2 33 [2] fc 11 [2] e8 0a [2] e7 10 [2] f9 0d [2] fb 0c [2] e0 0a [2] fc 0d [2] e0 22 }

  condition:
    any of them
}