rule TTP_XOR_QUAD_CurrentVersionRun_750e {
  strings:
    $key_750e = { 26 61 [2] 02 6f [2] 29 43 [2] 07 61 [2] 13 7a [2] 1c 60 [2] 02 7d [2] 00 7c [2] 1b 7a [2] 07 7d [2] 1b 52 }

  condition:
    any of them
}