rule TTP_XOR_QUAD_CurrentVersionRun_9153 {
  strings:
    $key_9153 = { c2 3c [2] e6 32 [2] cd 1e [2] e3 3c [2] f7 27 [2] f8 3d [2] e6 20 [2] e4 21 [2] ff 27 [2] e3 20 [2] ff 0f }

  condition:
    any of them
}