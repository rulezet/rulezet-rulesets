rule TTP_XOR_QUAD_CurrentVersionRun_417a {
  strings:
    $key_417a = { 12 15 [2] 36 1b [2] 1d 37 [2] 33 15 [2] 27 0e [2] 28 14 [2] 36 09 [2] 34 08 [2] 2f 0e [2] 33 09 [2] 2f 26 }

  condition:
    any of them
}