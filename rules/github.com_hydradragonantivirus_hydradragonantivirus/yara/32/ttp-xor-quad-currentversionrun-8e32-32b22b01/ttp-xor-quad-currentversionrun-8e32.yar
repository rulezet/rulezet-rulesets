rule TTP_XOR_QUAD_CurrentVersionRun_8e32 {
  strings:
    $key_8e32 = { dd 5d [2] f9 53 [2] d2 7f [2] fc 5d [2] e8 46 [2] e7 5c [2] f9 41 [2] fb 40 [2] e0 46 [2] fc 41 [2] e0 6e }

  condition:
    any of them
}