rule TTP_XOR_QUAD_CurrentVersionRun_7511 {
  strings:
    $key_7511 = { 26 7e [2] 02 70 [2] 29 5c [2] 07 7e [2] 13 65 [2] 1c 7f [2] 02 62 [2] 00 63 [2] 1b 65 [2] 07 62 [2] 1b 4d }

  condition:
    any of them
}