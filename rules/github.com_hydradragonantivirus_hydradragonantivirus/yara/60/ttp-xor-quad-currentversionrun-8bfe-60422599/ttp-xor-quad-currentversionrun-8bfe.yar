rule TTP_XOR_QUAD_CurrentVersionRun_8bfe {
  strings:
    $key_8bfe = { d8 91 [2] fc 9f [2] d7 b3 [2] f9 91 [2] ed 8a [2] e2 90 [2] fc 8d [2] fe 8c [2] e5 8a [2] f9 8d [2] e5 a2 }

  condition:
    any of them
}