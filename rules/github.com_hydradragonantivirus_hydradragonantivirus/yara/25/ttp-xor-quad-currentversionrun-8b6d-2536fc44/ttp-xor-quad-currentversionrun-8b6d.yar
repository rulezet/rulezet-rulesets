rule TTP_XOR_QUAD_CurrentVersionRun_8b6d {
  strings:
    $key_8b6d = { d8 02 [2] fc 0c [2] d7 20 [2] f9 02 [2] ed 19 [2] e2 03 [2] fc 1e [2] fe 1f [2] e5 19 [2] f9 1e [2] e5 31 }

  condition:
    any of them
}