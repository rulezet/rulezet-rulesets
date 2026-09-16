rule TTP_XOR_QUAD_CurrentVersionRun_6f3a {
  strings:
    $key_6f3a = { 3c 55 [2] 18 5b [2] 33 77 [2] 1d 55 [2] 09 4e [2] 06 54 [2] 18 49 [2] 1a 48 [2] 01 4e [2] 1d 49 [2] 01 66 }

  condition:
    any of them
}