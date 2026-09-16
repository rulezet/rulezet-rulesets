rule TTP_XOR_QUAD_CurrentVersionRun_8b7e {
  strings:
    $key_8b7e = { d8 11 [2] fc 1f [2] d7 33 [2] f9 11 [2] ed 0a [2] e2 10 [2] fc 0d [2] fe 0c [2] e5 0a [2] f9 0d [2] e5 22 }

  condition:
    any of them
}