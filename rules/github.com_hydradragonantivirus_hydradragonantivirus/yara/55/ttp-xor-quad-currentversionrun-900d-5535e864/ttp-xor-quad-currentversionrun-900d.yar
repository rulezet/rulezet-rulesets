rule TTP_XOR_QUAD_CurrentVersionRun_900d {
  strings:
    $key_900d = { c3 62 [2] e7 6c [2] cc 40 [2] e2 62 [2] f6 79 [2] f9 63 [2] e7 7e [2] e5 7f [2] fe 79 [2] e2 7e [2] fe 51 }

  condition:
    any of them
}