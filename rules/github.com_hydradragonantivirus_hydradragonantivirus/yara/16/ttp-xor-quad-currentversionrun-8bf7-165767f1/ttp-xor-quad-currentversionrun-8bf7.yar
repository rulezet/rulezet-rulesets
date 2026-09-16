rule TTP_XOR_QUAD_CurrentVersionRun_8bf7 {
  strings:
    $key_8bf7 = { d8 98 [2] fc 96 [2] d7 ba [2] f9 98 [2] ed 83 [2] e2 99 [2] fc 84 [2] fe 85 [2] e5 83 [2] f9 84 [2] e5 ab }

  condition:
    any of them
}