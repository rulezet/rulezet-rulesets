rule TTP_XOR_QUAD_CurrentVersionRun_725a {
  strings:
    $key_725a = { 21 35 [2] 05 3b [2] 2e 17 [2] 00 35 [2] 14 2e [2] 1b 34 [2] 05 29 [2] 07 28 [2] 1c 2e [2] 00 29 [2] 1c 06 }

  condition:
    any of them
}