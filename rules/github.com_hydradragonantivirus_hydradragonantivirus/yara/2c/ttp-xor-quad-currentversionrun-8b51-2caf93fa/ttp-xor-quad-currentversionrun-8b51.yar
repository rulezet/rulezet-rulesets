rule TTP_XOR_QUAD_CurrentVersionRun_8b51 {
  strings:
    $key_8b51 = { d8 3e [2] fc 30 [2] d7 1c [2] f9 3e [2] ed 25 [2] e2 3f [2] fc 22 [2] fe 23 [2] e5 25 [2] f9 22 [2] e5 0d }

  condition:
    any of them
}