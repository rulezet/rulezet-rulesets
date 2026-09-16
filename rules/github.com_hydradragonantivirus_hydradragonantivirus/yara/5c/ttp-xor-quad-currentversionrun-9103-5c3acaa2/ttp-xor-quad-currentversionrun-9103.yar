rule TTP_XOR_QUAD_CurrentVersionRun_9103 {
  strings:
    $key_9103 = { c2 6c [2] e6 62 [2] cd 4e [2] e3 6c [2] f7 77 [2] f8 6d [2] e6 70 [2] e4 71 [2] ff 77 [2] e3 70 [2] ff 5f }

  condition:
    any of them
}