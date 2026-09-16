rule TTP_XOR_QUAD_CurrentVersionRun_754a {
  strings:
    $key_754a = { 26 25 [2] 02 2b [2] 29 07 [2] 07 25 [2] 13 3e [2] 1c 24 [2] 02 39 [2] 00 38 [2] 1b 3e [2] 07 39 [2] 1b 16 }

  condition:
    any of them
}