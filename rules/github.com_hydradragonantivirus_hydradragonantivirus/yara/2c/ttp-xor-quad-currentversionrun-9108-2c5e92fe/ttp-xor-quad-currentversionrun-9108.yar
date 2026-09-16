rule TTP_XOR_QUAD_CurrentVersionRun_9108 {
  strings:
    $key_9108 = { c2 67 [2] e6 69 [2] cd 45 [2] e3 67 [2] f7 7c [2] f8 66 [2] e6 7b [2] e4 7a [2] ff 7c [2] e3 7b [2] ff 54 }

  condition:
    any of them
}