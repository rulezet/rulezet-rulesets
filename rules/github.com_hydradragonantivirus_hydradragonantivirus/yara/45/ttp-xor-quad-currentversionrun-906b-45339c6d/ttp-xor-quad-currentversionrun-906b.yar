rule TTP_XOR_QUAD_CurrentVersionRun_906b {
  strings:
    $key_906b = { c3 04 [2] e7 0a [2] cc 26 [2] e2 04 [2] f6 1f [2] f9 05 [2] e7 18 [2] e5 19 [2] fe 1f [2] e2 18 [2] fe 37 }

  condition:
    any of them
}