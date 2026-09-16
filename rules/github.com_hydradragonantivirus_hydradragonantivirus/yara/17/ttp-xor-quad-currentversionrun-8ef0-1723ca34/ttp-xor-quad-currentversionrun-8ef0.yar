rule TTP_XOR_QUAD_CurrentVersionRun_8ef0 {
  strings:
    $key_8ef0 = { dd 9f [2] f9 91 [2] d2 bd [2] fc 9f [2] e8 84 [2] e7 9e [2] f9 83 [2] fb 82 [2] e0 84 [2] fc 83 [2] e0 ac }

  condition:
    any of them
}