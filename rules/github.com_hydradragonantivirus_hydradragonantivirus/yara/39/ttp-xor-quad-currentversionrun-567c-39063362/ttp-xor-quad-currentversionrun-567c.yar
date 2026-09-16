rule TTP_XOR_QUAD_CurrentVersionRun_567c {
  strings:
    $key_567c = { 05 13 [2] 21 1d [2] 0a 31 [2] 24 13 [2] 30 08 [2] 3f 12 [2] 21 0f [2] 23 0e [2] 38 08 [2] 24 0f [2] 38 20 }

  condition:
    any of them
}