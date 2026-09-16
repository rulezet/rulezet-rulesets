rule TTP_XOR_QUAD_CurrentVersionRun_8be4 {
  strings:
    $key_8be4 = { d8 8b [2] fc 85 [2] d7 a9 [2] f9 8b [2] ed 90 [2] e2 8a [2] fc 97 [2] fe 96 [2] e5 90 [2] f9 97 [2] e5 b8 }

  condition:
    any of them
}