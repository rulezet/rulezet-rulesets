rule TTP_XOR_QUAD_CurrentVersionRun_9135 {
  strings:
    $key_9135 = { c2 5a [2] e6 54 [2] cd 78 [2] e3 5a [2] f7 41 [2] f8 5b [2] e6 46 [2] e4 47 [2] ff 41 [2] e3 46 [2] ff 69 }

  condition:
    any of them
}