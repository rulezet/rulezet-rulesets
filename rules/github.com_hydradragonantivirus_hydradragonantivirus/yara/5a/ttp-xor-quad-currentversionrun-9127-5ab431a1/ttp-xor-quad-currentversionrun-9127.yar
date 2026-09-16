rule TTP_XOR_QUAD_CurrentVersionRun_9127 {
  strings:
    $key_9127 = { c2 48 [2] e6 46 [2] cd 6a [2] e3 48 [2] f7 53 [2] f8 49 [2] e6 54 [2] e4 55 [2] ff 53 [2] e3 54 [2] ff 7b }

  condition:
    any of them
}