rule TTP_XOR_QUAD_CurrentVersionRun_7c0e {
  strings:
    $key_7c0e = { 2f 61 [2] 0b 6f [2] 20 43 [2] 0e 61 [2] 1a 7a [2] 15 60 [2] 0b 7d [2] 09 7c [2] 12 7a [2] 0e 7d [2] 12 52 }

  condition:
    any of them
}