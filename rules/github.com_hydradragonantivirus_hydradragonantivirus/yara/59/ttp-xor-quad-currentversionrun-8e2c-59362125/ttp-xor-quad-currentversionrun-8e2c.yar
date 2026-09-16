rule TTP_XOR_QUAD_CurrentVersionRun_8e2c {
  strings:
    $key_8e2c = { dd 43 [2] f9 4d [2] d2 61 [2] fc 43 [2] e8 58 [2] e7 42 [2] f9 5f [2] fb 5e [2] e0 58 [2] fc 5f [2] e0 70 }

  condition:
    any of them
}