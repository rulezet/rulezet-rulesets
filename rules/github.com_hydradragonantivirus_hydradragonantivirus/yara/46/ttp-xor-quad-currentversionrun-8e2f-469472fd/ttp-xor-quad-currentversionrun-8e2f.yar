rule TTP_XOR_QUAD_CurrentVersionRun_8e2f {
  strings:
    $key_8e2f = { dd 40 [2] f9 4e [2] d2 62 [2] fc 40 [2] e8 5b [2] e7 41 [2] f9 5c [2] fb 5d [2] e0 5b [2] fc 5c [2] e0 73 }

  condition:
    any of them
}