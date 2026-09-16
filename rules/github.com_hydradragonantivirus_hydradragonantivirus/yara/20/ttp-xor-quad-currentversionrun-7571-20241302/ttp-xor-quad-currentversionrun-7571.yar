rule TTP_XOR_QUAD_CurrentVersionRun_7571 {
  strings:
    $key_7571 = { 26 1e [2] 02 10 [2] 29 3c [2] 07 1e [2] 13 05 [2] 1c 1f [2] 02 02 [2] 00 03 [2] 1b 05 [2] 07 02 [2] 1b 2d }

  condition:
    any of them
}