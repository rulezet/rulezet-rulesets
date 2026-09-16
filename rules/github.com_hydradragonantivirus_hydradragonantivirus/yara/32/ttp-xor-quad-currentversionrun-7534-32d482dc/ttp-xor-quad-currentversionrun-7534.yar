rule TTP_XOR_QUAD_CurrentVersionRun_7534 {
  strings:
    $key_7534 = { 26 5b [2] 02 55 [2] 29 79 [2] 07 5b [2] 13 40 [2] 1c 5a [2] 02 47 [2] 00 46 [2] 1b 40 [2] 07 47 [2] 1b 68 }

  condition:
    any of them
}