rule TTP_XOR_QUAD_CurrentVersionRun_8e02 {
  strings:
    $key_8e02 = { dd 6d [2] f9 63 [2] d2 4f [2] fc 6d [2] e8 76 [2] e7 6c [2] f9 71 [2] fb 70 [2] e0 76 [2] fc 71 [2] e0 5e }

  condition:
    any of them
}