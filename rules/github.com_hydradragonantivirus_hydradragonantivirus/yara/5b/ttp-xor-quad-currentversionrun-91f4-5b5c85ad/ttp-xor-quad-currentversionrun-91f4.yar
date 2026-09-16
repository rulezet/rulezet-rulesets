rule TTP_XOR_QUAD_CurrentVersionRun_91f4 {
  strings:
    $key_91f4 = { c2 9b [2] e6 95 [2] cd b9 [2] e3 9b [2] f7 80 [2] f8 9a [2] e6 87 [2] e4 86 [2] ff 80 [2] e3 87 [2] ff a8 }

  condition:
    any of them
}