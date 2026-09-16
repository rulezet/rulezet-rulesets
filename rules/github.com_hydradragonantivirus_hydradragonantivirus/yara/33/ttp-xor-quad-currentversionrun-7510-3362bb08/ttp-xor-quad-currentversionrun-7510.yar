rule TTP_XOR_QUAD_CurrentVersionRun_7510 {
  strings:
    $key_7510 = { 26 7f [2] 02 71 [2] 29 5d [2] 07 7f [2] 13 64 [2] 1c 7e [2] 02 63 [2] 00 62 [2] 1b 64 [2] 07 63 [2] 1b 4c }

  condition:
    any of them
}