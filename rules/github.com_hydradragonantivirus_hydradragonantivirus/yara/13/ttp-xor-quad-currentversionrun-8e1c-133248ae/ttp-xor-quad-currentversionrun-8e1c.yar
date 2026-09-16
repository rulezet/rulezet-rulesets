rule TTP_XOR_QUAD_CurrentVersionRun_8e1c {
  strings:
    $key_8e1c = { dd 73 [2] f9 7d [2] d2 51 [2] fc 73 [2] e8 68 [2] e7 72 [2] f9 6f [2] fb 6e [2] e0 68 [2] fc 6f [2] e0 40 }

  condition:
    any of them
}