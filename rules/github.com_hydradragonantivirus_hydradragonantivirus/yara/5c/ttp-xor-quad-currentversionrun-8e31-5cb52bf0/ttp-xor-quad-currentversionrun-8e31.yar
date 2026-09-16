rule TTP_XOR_QUAD_CurrentVersionRun_8e31 {
  strings:
    $key_8e31 = { dd 5e [2] f9 50 [2] d2 7c [2] fc 5e [2] e8 45 [2] e7 5f [2] f9 42 [2] fb 43 [2] e0 45 [2] fc 42 [2] e0 6d }

  condition:
    any of them
}