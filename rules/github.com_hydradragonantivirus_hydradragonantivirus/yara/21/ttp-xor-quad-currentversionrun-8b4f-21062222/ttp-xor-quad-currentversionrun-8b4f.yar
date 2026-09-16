rule TTP_XOR_QUAD_CurrentVersionRun_8b4f {
  strings:
    $key_8b4f = { d8 20 [2] fc 2e [2] d7 02 [2] f9 20 [2] ed 3b [2] e2 21 [2] fc 3c [2] fe 3d [2] e5 3b [2] f9 3c [2] e5 13 }

  condition:
    any of them
}