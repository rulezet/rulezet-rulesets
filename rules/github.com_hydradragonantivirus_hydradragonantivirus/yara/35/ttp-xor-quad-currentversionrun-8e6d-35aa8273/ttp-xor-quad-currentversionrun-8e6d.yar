rule TTP_XOR_QUAD_CurrentVersionRun_8e6d {
  strings:
    $key_8e6d = { dd 02 [2] f9 0c [2] d2 20 [2] fc 02 [2] e8 19 [2] e7 03 [2] f9 1e [2] fb 1f [2] e0 19 [2] fc 1e [2] e0 31 }

  condition:
    any of them
}