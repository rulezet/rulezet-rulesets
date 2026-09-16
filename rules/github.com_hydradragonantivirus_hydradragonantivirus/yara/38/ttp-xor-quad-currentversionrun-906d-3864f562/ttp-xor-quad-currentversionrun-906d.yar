rule TTP_XOR_QUAD_CurrentVersionRun_906d {
  strings:
    $key_906d = { c3 02 [2] e7 0c [2] cc 20 [2] e2 02 [2] f6 19 [2] f9 03 [2] e7 1e [2] e5 1f [2] fe 19 [2] e2 1e [2] fe 31 }

  condition:
    any of them
}