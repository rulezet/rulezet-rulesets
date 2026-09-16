rule TTP_XOR_QUAD_CurrentVersionRun_8e11 {
  strings:
    $key_8e11 = { dd 7e [2] f9 70 [2] d2 5c [2] fc 7e [2] e8 65 [2] e7 7f [2] f9 62 [2] fb 63 [2] e0 65 [2] fc 62 [2] e0 4d }

  condition:
    any of them
}