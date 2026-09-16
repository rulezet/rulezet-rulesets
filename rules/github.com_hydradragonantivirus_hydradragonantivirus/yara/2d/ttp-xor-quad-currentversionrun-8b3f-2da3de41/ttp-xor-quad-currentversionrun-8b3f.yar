rule TTP_XOR_QUAD_CurrentVersionRun_8b3f {
  strings:
    $key_8b3f = { d8 50 [2] fc 5e [2] d7 72 [2] f9 50 [2] ed 4b [2] e2 51 [2] fc 4c [2] fe 4d [2] e5 4b [2] f9 4c [2] e5 63 }

  condition:
    any of them
}