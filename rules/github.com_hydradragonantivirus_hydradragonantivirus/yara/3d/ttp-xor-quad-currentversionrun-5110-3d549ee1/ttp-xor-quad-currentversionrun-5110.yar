rule TTP_XOR_QUAD_CurrentVersionRun_5110 {
  strings:
    $key_5110 = { 02 7f [2] 26 71 [2] 0d 5d [2] 23 7f [2] 37 64 [2] 38 7e [2] 26 63 [2] 24 62 [2] 3f 64 [2] 23 63 [2] 3f 4c }

  condition:
    any of them
}