rule TTP_XOR_QUAD_CurrentVersionRun_903d {
  strings:
    $key_903d = { c3 52 [2] e7 5c [2] cc 70 [2] e2 52 [2] f6 49 [2] f9 53 [2] e7 4e [2] e5 4f [2] fe 49 [2] e2 4e [2] fe 61 }

  condition:
    any of them
}