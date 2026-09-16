rule TTP_XOR_QUAD_CurrentVersionRun_8b2e {
  strings:
    $key_8b2e = { d8 41 [2] fc 4f [2] d7 63 [2] f9 41 [2] ed 5a [2] e2 40 [2] fc 5d [2] fe 5c [2] e5 5a [2] f9 5d [2] e5 72 }

  condition:
    any of them
}