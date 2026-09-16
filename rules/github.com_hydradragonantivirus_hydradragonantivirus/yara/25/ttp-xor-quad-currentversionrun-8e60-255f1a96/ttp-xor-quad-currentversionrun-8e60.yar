rule TTP_XOR_QUAD_CurrentVersionRun_8e60 {
  strings:
    $key_8e60 = { dd 0f [2] f9 01 [2] d2 2d [2] fc 0f [2] e8 14 [2] e7 0e [2] f9 13 [2] fb 12 [2] e0 14 [2] fc 13 [2] e0 3c }

  condition:
    any of them
}