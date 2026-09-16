rule TTP_XOR_QUAD_CurrentVersionRun_8bfb {
  strings:
    $key_8bfb = { d8 94 [2] fc 9a [2] d7 b6 [2] f9 94 [2] ed 8f [2] e2 95 [2] fc 88 [2] fe 89 [2] e5 8f [2] f9 88 [2] e5 a7 }

  condition:
    any of them
}