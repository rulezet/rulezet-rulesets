rule TTP_XOR_QUAD_CurrentVersionRun_7544 {
  strings:
    $key_7544 = { 26 2b [2] 02 25 [2] 29 09 [2] 07 2b [2] 13 30 [2] 1c 2a [2] 02 37 [2] 00 36 [2] 1b 30 [2] 07 37 [2] 1b 18 }

  condition:
    any of them
}