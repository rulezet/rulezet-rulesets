rule TTP_XOR_QUAD_CurrentVersionRun_8bf9 {
  strings:
    $key_8bf9 = { d8 96 [2] fc 98 [2] d7 b4 [2] f9 96 [2] ed 8d [2] e2 97 [2] fc 8a [2] fe 8b [2] e5 8d [2] f9 8a [2] e5 a5 }

  condition:
    any of them
}