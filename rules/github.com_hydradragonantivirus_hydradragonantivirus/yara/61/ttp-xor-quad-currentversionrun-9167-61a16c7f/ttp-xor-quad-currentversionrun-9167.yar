rule TTP_XOR_QUAD_CurrentVersionRun_9167 {
  strings:
    $key_9167 = { c2 08 [2] e6 06 [2] cd 2a [2] e3 08 [2] f7 13 [2] f8 09 [2] e6 14 [2] e4 15 [2] ff 13 [2] e3 14 [2] ff 3b }

  condition:
    any of them
}