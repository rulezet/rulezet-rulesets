rule TTP_XOR_QUAD_CurrentVersionRun_244a {
  strings:
    $key_244a = { 77 25 [2] 53 2b [2] 78 07 [2] 56 25 [2] 42 3e [2] 4d 24 [2] 53 39 [2] 51 38 [2] 4a 3e [2] 56 39 [2] 4a 16 }

  condition:
    any of them
}