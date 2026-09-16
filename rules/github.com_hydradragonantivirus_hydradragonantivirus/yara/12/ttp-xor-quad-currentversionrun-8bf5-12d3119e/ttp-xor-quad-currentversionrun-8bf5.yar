rule TTP_XOR_QUAD_CurrentVersionRun_8bf5 {
  strings:
    $key_8bf5 = { d8 9a [2] fc 94 [2] d7 b8 [2] f9 9a [2] ed 81 [2] e2 9b [2] fc 86 [2] fe 87 [2] e5 81 [2] f9 86 [2] e5 a9 }

  condition:
    any of them
}