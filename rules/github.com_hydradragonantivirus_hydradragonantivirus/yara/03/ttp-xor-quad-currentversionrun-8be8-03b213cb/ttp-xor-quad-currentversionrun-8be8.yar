rule TTP_XOR_QUAD_CurrentVersionRun_8be8 {
  strings:
    $key_8be8 = { d8 87 [2] fc 89 [2] d7 a5 [2] f9 87 [2] ed 9c [2] e2 86 [2] fc 9b [2] fe 9a [2] e5 9c [2] f9 9b [2] e5 b4 }

  condition:
    any of them
}