rule TTP_XOR_QUAD_CurrentVersionRun_9146 {
  strings:
    $key_9146 = { c2 29 [2] e6 27 [2] cd 0b [2] e3 29 [2] f7 32 [2] f8 28 [2] e6 35 [2] e4 34 [2] ff 32 [2] e3 35 [2] ff 1a }

  condition:
    any of them
}