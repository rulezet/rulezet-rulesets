rule TTP_XOR_QUAD_CurrentVersionRun_8b02 {
  strings:
    $key_8b02 = { d8 6d [2] fc 63 [2] d7 4f [2] f9 6d [2] ed 76 [2] e2 6c [2] fc 71 [2] fe 70 [2] e5 76 [2] f9 71 [2] e5 5e }

  condition:
    any of them
}