rule TTP_XOR_QUAD_CurrentVersionRun_9157 {
  strings:
    $key_9157 = { c2 38 [2] e6 36 [2] cd 1a [2] e3 38 [2] f7 23 [2] f8 39 [2] e6 24 [2] e4 25 [2] ff 23 [2] e3 24 [2] ff 0b }

  condition:
    any of them
}