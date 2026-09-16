rule TTP_XOR_QUAD_CurrentVersionRun_2b7a {
  strings:
    $key_2b7a = { 78 15 [2] 5c 1b [2] 77 37 [2] 59 15 [2] 4d 0e [2] 42 14 [2] 5c 09 [2] 5e 08 [2] 45 0e [2] 59 09 [2] 45 26 }

  condition:
    any of them
}