rule TTP_XOR_QUAD_CurrentVersionRun_751c {
  strings:
    $key_751c = { 26 73 [2] 02 7d [2] 29 51 [2] 07 73 [2] 13 68 [2] 1c 72 [2] 02 6f [2] 00 6e [2] 1b 68 [2] 07 6f [2] 1b 40 }

  condition:
    any of them
}