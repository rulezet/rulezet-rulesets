rule TTP_XOR_QUAD_CurrentVersionRun_8b1f {
  strings:
    $key_8b1f = { d8 70 [2] fc 7e [2] d7 52 [2] f9 70 [2] ed 6b [2] e2 71 [2] fc 6c [2] fe 6d [2] e5 6b [2] f9 6c [2] e5 43 }

  condition:
    any of them
}