rule TTP_XOR_QUAD_CurrentVersionRun_916a {
  strings:
    $key_916a = { c2 05 [2] e6 0b [2] cd 27 [2] e3 05 [2] f7 1e [2] f8 04 [2] e6 19 [2] e4 18 [2] ff 1e [2] e3 19 [2] ff 36 }

  condition:
    any of them
}