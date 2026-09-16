rule TTP_XOR_QUAD_CurrentVersionRun_8ef7 {
  strings:
    $key_8ef7 = { dd 98 [2] f9 96 [2] d2 ba [2] fc 98 [2] e8 83 [2] e7 99 [2] f9 84 [2] fb 85 [2] e0 83 [2] fc 84 [2] e0 ab }

  condition:
    any of them
}