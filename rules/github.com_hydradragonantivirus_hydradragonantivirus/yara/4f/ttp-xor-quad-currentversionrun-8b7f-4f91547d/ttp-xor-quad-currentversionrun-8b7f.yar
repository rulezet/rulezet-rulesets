rule TTP_XOR_QUAD_CurrentVersionRun_8b7f {
  strings:
    $key_8b7f = { d8 10 [2] fc 1e [2] d7 32 [2] f9 10 [2] ed 0b [2] e2 11 [2] fc 0c [2] fe 0d [2] e5 0b [2] f9 0c [2] e5 23 }

  condition:
    any of them
}