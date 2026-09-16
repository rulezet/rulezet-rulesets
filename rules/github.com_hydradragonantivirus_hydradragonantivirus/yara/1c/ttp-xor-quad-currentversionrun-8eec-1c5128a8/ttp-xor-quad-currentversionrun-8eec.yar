rule TTP_XOR_QUAD_CurrentVersionRun_8eec {
  strings:
    $key_8eec = { dd 83 [2] f9 8d [2] d2 a1 [2] fc 83 [2] e8 98 [2] e7 82 [2] f9 9f [2] fb 9e [2] e0 98 [2] fc 9f [2] e0 b0 }

  condition:
    any of them
}