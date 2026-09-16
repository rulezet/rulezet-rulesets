rule TTP_XOR_QUAD_CurrentVersionRun_8be5 {
  strings:
    $key_8be5 = { d8 8a [2] fc 84 [2] d7 a8 [2] f9 8a [2] ed 91 [2] e2 8b [2] fc 96 [2] fe 97 [2] e5 91 [2] f9 96 [2] e5 b9 }

  condition:
    any of them
}