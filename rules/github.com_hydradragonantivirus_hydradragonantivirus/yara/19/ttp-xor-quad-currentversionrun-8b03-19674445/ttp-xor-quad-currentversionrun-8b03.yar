rule TTP_XOR_QUAD_CurrentVersionRun_8b03 {
  strings:
    $key_8b03 = { d8 6c [2] fc 62 [2] d7 4e [2] f9 6c [2] ed 77 [2] e2 6d [2] fc 70 [2] fe 71 [2] e5 77 [2] f9 70 [2] e5 5f }

  condition:
    any of them
}