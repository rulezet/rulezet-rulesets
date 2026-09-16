rule TTP_XOR_QUAD_CurrentVersionRun_8b42 {
  strings:
    $key_8b42 = { d8 2d [2] fc 23 [2] d7 0f [2] f9 2d [2] ed 36 [2] e2 2c [2] fc 31 [2] fe 30 [2] e5 36 [2] f9 31 [2] e5 1e }

  condition:
    any of them
}