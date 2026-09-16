rule TTP_XOR_QUAD_CurrentVersionRun_9124 {
  strings:
    $key_9124 = { c2 4b [2] e6 45 [2] cd 69 [2] e3 4b [2] f7 50 [2] f8 4a [2] e6 57 [2] e4 56 [2] ff 50 [2] e3 57 [2] ff 78 }

  condition:
    any of them
}