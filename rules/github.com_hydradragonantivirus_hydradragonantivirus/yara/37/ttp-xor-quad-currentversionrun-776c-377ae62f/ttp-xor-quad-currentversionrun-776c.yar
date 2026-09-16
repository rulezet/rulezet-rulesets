rule TTP_XOR_QUAD_CurrentVersionRun_776c {
  strings:
    $key_776c = { 24 03 [2] 00 0d [2] 2b 21 [2] 05 03 [2] 11 18 [2] 1e 02 [2] 00 1f [2] 02 1e [2] 19 18 [2] 05 1f [2] 19 30 }

  condition:
    any of them
}