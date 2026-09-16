rule TTP_XOR_QUAD_CurrentVersionRun_9106 {
  strings:
    $key_9106 = { c2 69 [2] e6 67 [2] cd 4b [2] e3 69 [2] f7 72 [2] f8 68 [2] e6 75 [2] e4 74 [2] ff 72 [2] e3 75 [2] ff 5a }

  condition:
    any of them
}