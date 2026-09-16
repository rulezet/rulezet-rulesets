rule TTP_XOR_QUAD_CurrentVersionRun_8b3c {
  strings:
    $key_8b3c = { d8 53 [2] fc 5d [2] d7 71 [2] f9 53 [2] ed 48 [2] e2 52 [2] fc 4f [2] fe 4e [2] e5 48 [2] f9 4f [2] e5 60 }

  condition:
    any of them
}