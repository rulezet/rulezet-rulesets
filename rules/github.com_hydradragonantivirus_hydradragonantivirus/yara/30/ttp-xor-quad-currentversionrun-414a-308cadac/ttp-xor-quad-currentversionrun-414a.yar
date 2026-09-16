rule TTP_XOR_QUAD_CurrentVersionRun_414a {
  strings:
    $key_414a = { 12 25 [2] 36 2b [2] 1d 07 [2] 33 25 [2] 27 3e [2] 28 24 [2] 36 39 [2] 34 38 [2] 2f 3e [2] 33 39 [2] 2f 16 }

  condition:
    any of them
}