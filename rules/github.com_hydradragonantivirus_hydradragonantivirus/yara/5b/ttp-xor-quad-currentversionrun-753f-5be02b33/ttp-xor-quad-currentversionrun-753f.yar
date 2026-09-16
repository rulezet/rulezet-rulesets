rule TTP_XOR_QUAD_CurrentVersionRun_753f {
  strings:
    $key_753f = { 26 50 [2] 02 5e [2] 29 72 [2] 07 50 [2] 13 4b [2] 1c 51 [2] 02 4c [2] 00 4d [2] 1b 4b [2] 07 4c [2] 1b 63 }

  condition:
    any of them
}