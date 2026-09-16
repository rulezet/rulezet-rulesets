rule TTP_XOR_QUAD_CurrentVersionRun_903e {
  strings:
    $key_903e = { c3 51 [2] e7 5f [2] cc 73 [2] e2 51 [2] f6 4a [2] f9 50 [2] e7 4d [2] e5 4c [2] fe 4a [2] e2 4d [2] fe 62 }

  condition:
    any of them
}