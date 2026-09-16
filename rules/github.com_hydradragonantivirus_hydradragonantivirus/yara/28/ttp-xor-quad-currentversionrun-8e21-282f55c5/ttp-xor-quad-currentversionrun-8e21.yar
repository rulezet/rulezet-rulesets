rule TTP_XOR_QUAD_CurrentVersionRun_8e21 {
  strings:
    $key_8e21 = { dd 4e [2] f9 40 [2] d2 6c [2] fc 4e [2] e8 55 [2] e7 4f [2] f9 52 [2] fb 53 [2] e0 55 [2] fc 52 [2] e0 7d }

  condition:
    any of them
}