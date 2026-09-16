rule TTP_XOR_QUAD_CurrentVersionRun_8b76 {
  strings:
    $key_8b76 = { d8 19 [2] fc 17 [2] d7 3b [2] f9 19 [2] ed 02 [2] e2 18 [2] fc 05 [2] fe 04 [2] e5 02 [2] f9 05 [2] e5 2a }

  condition:
    any of them
}