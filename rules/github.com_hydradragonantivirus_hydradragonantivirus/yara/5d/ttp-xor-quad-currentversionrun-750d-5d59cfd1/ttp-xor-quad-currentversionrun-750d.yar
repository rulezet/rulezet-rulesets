rule TTP_XOR_QUAD_CurrentVersionRun_750d {
  strings:
    $key_750d = { 26 62 [2] 02 6c [2] 29 40 [2] 07 62 [2] 13 79 [2] 1c 63 [2] 02 7e [2] 00 7f [2] 1b 79 [2] 07 7e [2] 1b 51 }

  condition:
    any of them
}