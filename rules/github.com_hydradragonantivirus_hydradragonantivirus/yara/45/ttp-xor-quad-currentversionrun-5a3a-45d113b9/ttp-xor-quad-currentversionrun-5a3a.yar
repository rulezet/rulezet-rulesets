rule TTP_XOR_QUAD_CurrentVersionRun_5a3a {
  strings:
    $key_5a3a = { 09 55 [2] 2d 5b [2] 06 77 [2] 28 55 [2] 3c 4e [2] 33 54 [2] 2d 49 [2] 2f 48 [2] 34 4e [2] 28 49 [2] 34 66 }

  condition:
    any of them
}