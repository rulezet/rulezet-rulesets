rule TTP_XOR_QUAD_CurrentVersionRun_901f {
  strings:
    $key_901f = { c3 70 [2] e7 7e [2] cc 52 [2] e2 70 [2] f6 6b [2] f9 71 [2] e7 6c [2] e5 6d [2] fe 6b [2] e2 6c [2] fe 43 }

  condition:
    any of them
}