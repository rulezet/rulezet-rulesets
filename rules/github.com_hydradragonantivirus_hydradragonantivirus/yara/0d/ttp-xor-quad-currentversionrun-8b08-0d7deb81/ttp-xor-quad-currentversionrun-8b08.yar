rule TTP_XOR_QUAD_CurrentVersionRun_8b08 {
  strings:
    $key_8b08 = { d8 67 [2] fc 69 [2] d7 45 [2] f9 67 [2] ed 7c [2] e2 66 [2] fc 7b [2] fe 7a [2] e5 7c [2] f9 7b [2] e5 54 }

  condition:
    any of them
}