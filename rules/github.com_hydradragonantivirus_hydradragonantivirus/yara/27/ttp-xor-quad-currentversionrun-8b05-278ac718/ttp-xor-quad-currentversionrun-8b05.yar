rule TTP_XOR_QUAD_CurrentVersionRun_8b05 {
  strings:
    $key_8b05 = { d8 6a [2] fc 64 [2] d7 48 [2] f9 6a [2] ed 71 [2] e2 6b [2] fc 76 [2] fe 77 [2] e5 71 [2] f9 76 [2] e5 59 }

  condition:
    any of them
}