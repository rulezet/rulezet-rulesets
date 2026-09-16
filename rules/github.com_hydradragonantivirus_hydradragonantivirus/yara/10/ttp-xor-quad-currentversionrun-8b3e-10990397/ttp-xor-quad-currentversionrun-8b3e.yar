rule TTP_XOR_QUAD_CurrentVersionRun_8b3e {
  strings:
    $key_8b3e = { d8 51 [2] fc 5f [2] d7 73 [2] f9 51 [2] ed 4a [2] e2 50 [2] fc 4d [2] fe 4c [2] e5 4a [2] f9 4d [2] e5 62 }

  condition:
    any of them
}