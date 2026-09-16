rule TTP_XOR_QUAD_CurrentVersionRun_8b6c {
  strings:
    $key_8b6c = { d8 03 [2] fc 0d [2] d7 21 [2] f9 03 [2] ed 18 [2] e2 02 [2] fc 1f [2] fe 1e [2] e5 18 [2] f9 1f [2] e5 30 }

  condition:
    any of them
}