rule TTP_XOR_QUAD_CurrentVersionRun_8beb {
  strings:
    $key_8beb = { d8 84 [2] fc 8a [2] d7 a6 [2] f9 84 [2] ed 9f [2] e2 85 [2] fc 98 [2] fe 99 [2] e5 9f [2] f9 98 [2] e5 b7 }

  condition:
    any of them
}