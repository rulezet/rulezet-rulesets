rule TTP_XOR_QUAD_CurrentVersionRun_777c {
  strings:
    $key_777c = { 24 13 [2] 00 1d [2] 2b 31 [2] 05 13 [2] 11 08 [2] 1e 12 [2] 00 0f [2] 02 0e [2] 19 08 [2] 05 0f [2] 19 20 }

  condition:
    any of them
}