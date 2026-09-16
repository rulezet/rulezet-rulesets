rule TTP_XOR_QUAD_CurrentVersionRun_9163 {
  strings:
    $key_9163 = { c2 0c [2] e6 02 [2] cd 2e [2] e3 0c [2] f7 17 [2] f8 0d [2] e6 10 [2] e4 11 [2] ff 17 [2] e3 10 [2] ff 3f }

  condition:
    any of them
}