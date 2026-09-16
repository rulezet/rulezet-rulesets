rule TTP_XOR_QUAD_CurrentVersionRun_7b3a {
  strings:
    $key_7b3a = { 28 55 [2] 0c 5b [2] 27 77 [2] 09 55 [2] 1d 4e [2] 12 54 [2] 0c 49 [2] 0e 48 [2] 15 4e [2] 09 49 [2] 15 66 }

  condition:
    any of them
}