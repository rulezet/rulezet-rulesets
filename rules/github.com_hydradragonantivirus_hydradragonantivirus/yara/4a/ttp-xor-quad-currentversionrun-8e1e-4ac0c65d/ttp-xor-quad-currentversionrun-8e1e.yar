rule TTP_XOR_QUAD_CurrentVersionRun_8e1e {
  strings:
    $key_8e1e = { dd 71 [2] f9 7f [2] d2 53 [2] fc 71 [2] e8 6a [2] e7 70 [2] f9 6d [2] fb 6c [2] e0 6a [2] fc 6d [2] e0 42 }

  condition:
    any of them
}