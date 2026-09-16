rule TTP_XOR_QUAD_CurrentVersionRun_9109 {
  strings:
    $key_9109 = { c2 66 [2] e6 68 [2] cd 44 [2] e3 66 [2] f7 7d [2] f8 67 [2] e6 7a [2] e4 7b [2] ff 7d [2] e3 7a [2] ff 55 }

  condition:
    any of them
}