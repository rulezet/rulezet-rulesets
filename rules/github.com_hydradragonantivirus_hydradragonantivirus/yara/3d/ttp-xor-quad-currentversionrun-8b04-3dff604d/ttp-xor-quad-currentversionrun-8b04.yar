rule TTP_XOR_QUAD_CurrentVersionRun_8b04 {
  strings:
    $key_8b04 = { d8 6b [2] fc 65 [2] d7 49 [2] f9 6b [2] ed 70 [2] e2 6a [2] fc 77 [2] fe 76 [2] e5 70 [2] f9 77 [2] e5 58 }

  condition:
    any of them
}