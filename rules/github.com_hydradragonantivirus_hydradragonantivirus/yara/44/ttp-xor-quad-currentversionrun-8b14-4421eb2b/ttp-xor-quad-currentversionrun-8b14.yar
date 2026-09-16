rule TTP_XOR_QUAD_CurrentVersionRun_8b14 {
  strings:
    $key_8b14 = { d8 7b [2] fc 75 [2] d7 59 [2] f9 7b [2] ed 60 [2] e2 7a [2] fc 67 [2] fe 66 [2] e5 60 [2] f9 67 [2] e5 48 }

  condition:
    any of them
}