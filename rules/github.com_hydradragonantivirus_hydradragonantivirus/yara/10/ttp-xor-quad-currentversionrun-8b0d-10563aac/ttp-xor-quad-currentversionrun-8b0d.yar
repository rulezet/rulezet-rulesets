rule TTP_XOR_QUAD_CurrentVersionRun_8b0d {
  strings:
    $key_8b0d = { d8 62 [2] fc 6c [2] d7 40 [2] f9 62 [2] ed 79 [2] e2 63 [2] fc 7e [2] fe 7f [2] e5 79 [2] f9 7e [2] e5 51 }

  condition:
    any of them
}