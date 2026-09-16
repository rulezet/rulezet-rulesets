rule TTP_XOR_QUAD_CurrentVersionRun_8b01 {
  strings:
    $key_8b01 = { d8 6e [2] fc 60 [2] d7 4c [2] f9 6e [2] ed 75 [2] e2 6f [2] fc 72 [2] fe 73 [2] e5 75 [2] f9 72 [2] e5 5d }

  condition:
    any of them
}