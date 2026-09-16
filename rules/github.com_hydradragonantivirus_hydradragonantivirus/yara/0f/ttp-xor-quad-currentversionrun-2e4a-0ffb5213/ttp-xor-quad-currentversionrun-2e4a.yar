rule TTP_XOR_QUAD_CurrentVersionRun_2e4a {
  strings:
    $key_2e4a = { 7d 25 [2] 59 2b [2] 72 07 [2] 5c 25 [2] 48 3e [2] 47 24 [2] 59 39 [2] 5b 38 [2] 40 3e [2] 5c 39 [2] 40 16 }

  condition:
    any of them
}