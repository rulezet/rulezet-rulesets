rule TTP_XOR_QUAD_CurrentVersionRun_415a {
  strings:
    $key_415a = { 12 35 [2] 36 3b [2] 1d 17 [2] 33 35 [2] 27 2e [2] 28 34 [2] 36 29 [2] 34 28 [2] 2f 2e [2] 33 29 [2] 2f 06 }

  condition:
    any of them
}