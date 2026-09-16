rule TTP_XOR_QUAD_CurrentVersionRun_674a {
  strings:
    $key_674a = { 34 25 [2] 10 2b [2] 3b 07 [2] 15 25 [2] 01 3e [2] 0e 24 [2] 10 39 [2] 12 38 [2] 09 3e [2] 15 39 [2] 09 16 }

  condition:
    any of them
}