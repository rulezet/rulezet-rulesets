rule TTP_XOR_QUAD_CurrentVersionRun_8b24 {
  strings:
    $key_8b24 = { d8 4b [2] fc 45 [2] d7 69 [2] f9 4b [2] ed 50 [2] e2 4a [2] fc 57 [2] fe 56 [2] e5 50 [2] f9 57 [2] e5 78 }

  condition:
    any of them
}