rule TTP_XOR_QUAD_CurrentVersionRun_911b {
  strings:
    $key_911b = { c2 74 [2] e6 7a [2] cd 56 [2] e3 74 [2] f7 6f [2] f8 75 [2] e6 68 [2] e4 69 [2] ff 6f [2] e3 68 [2] ff 47 }

  condition:
    any of them
}