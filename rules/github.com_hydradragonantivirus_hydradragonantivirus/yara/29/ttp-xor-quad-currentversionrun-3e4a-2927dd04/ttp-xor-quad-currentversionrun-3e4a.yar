rule TTP_XOR_QUAD_CurrentVersionRun_3e4a {
  strings:
    $key_3e4a = { 6d 25 [2] 49 2b [2] 62 07 [2] 4c 25 [2] 58 3e [2] 57 24 [2] 49 39 [2] 4b 38 [2] 50 3e [2] 4c 39 [2] 50 16 }

  condition:
    any of them
}