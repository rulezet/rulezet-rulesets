rule TTP_XOR_QUAD_CurrentVersionRun_915a {
  strings:
    $key_915a = { c2 35 [2] e6 3b [2] cd 17 [2] e3 35 [2] f7 2e [2] f8 34 [2] e6 29 [2] e4 28 [2] ff 2e [2] e3 29 [2] ff 06 }

  condition:
    any of them
}