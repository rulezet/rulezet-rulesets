rule TTP_XOR_QUAD_CurrentVersionRun_8e2e {
  strings:
    $key_8e2e = { dd 41 [2] f9 4f [2] d2 63 [2] fc 41 [2] e8 5a [2] e7 40 [2] f9 5d [2] fb 5c [2] e0 5a [2] fc 5d [2] e0 72 }

  condition:
    any of them
}