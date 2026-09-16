rule TTP_XOR_QUAD_CurrentVersionRun_415d {
  strings:
    $key_415d = { 12 32 [2] 36 3c [2] 1d 10 [2] 33 32 [2] 27 29 [2] 28 33 [2] 36 2e [2] 34 2f [2] 2f 29 [2] 33 2e [2] 2f 01 }

  condition:
    any of them
}