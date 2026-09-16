rule TTP_XOR_QUAD_CurrentVersionRun_9134 {
  strings:
    $key_9134 = { c2 5b [2] e6 55 [2] cd 79 [2] e3 5b [2] f7 40 [2] f8 5a [2] e6 47 [2] e4 46 [2] ff 40 [2] e3 47 [2] ff 68 }

  condition:
    any of them
}