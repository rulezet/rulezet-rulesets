rule TTP_XOR_QUAD_CurrentVersionRun_90ef {
  strings:
    $key_90ef = { c3 80 [2] e7 8e [2] cc a2 [2] e2 80 [2] f6 9b [2] f9 81 [2] e7 9c [2] e5 9d [2] fe 9b [2] e2 9c [2] fe b3 }

  condition:
    any of them
}