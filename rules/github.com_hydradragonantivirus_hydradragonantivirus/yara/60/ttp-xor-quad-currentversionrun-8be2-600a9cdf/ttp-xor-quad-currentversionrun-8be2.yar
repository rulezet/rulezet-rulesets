rule TTP_XOR_QUAD_CurrentVersionRun_8be2 {
  strings:
    $key_8be2 = { d8 8d [2] fc 83 [2] d7 af [2] f9 8d [2] ed 96 [2] e2 8c [2] fc 91 [2] fe 90 [2] e5 96 [2] f9 91 [2] e5 be }

  condition:
    any of them
}