rule TTP_XOR_QUAD_CurrentVersionRun_911a {
  strings:
    $key_911a = { c2 75 [2] e6 7b [2] cd 57 [2] e3 75 [2] f7 6e [2] f8 74 [2] e6 69 [2] e4 68 [2] ff 6e [2] e3 69 [2] ff 46 }

  condition:
    any of them
}