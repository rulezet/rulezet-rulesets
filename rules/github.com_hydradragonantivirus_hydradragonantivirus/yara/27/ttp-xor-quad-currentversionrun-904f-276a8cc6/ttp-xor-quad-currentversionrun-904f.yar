rule TTP_XOR_QUAD_CurrentVersionRun_904f {
  strings:
    $key_904f = { c3 20 [2] e7 2e [2] cc 02 [2] e2 20 [2] f6 3b [2] f9 21 [2] e7 3c [2] e5 3d [2] fe 3b [2] e2 3c [2] fe 13 }

  condition:
    any of them
}