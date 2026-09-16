rule TTP_XOR_QUAD_CurrentVersionRun_8b38 {
  strings:
    $key_8b38 = { d8 57 [2] fc 59 [2] d7 75 [2] f9 57 [2] ed 4c [2] e2 56 [2] fc 4b [2] fe 4a [2] e5 4c [2] f9 4b [2] e5 64 }

  condition:
    any of them
}