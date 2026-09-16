rule TTP_XOR_QUAD_CurrentVersionRun_5c0e {
  strings:
    $key_5c0e = { 0f 61 [2] 2b 6f [2] 00 43 [2] 2e 61 [2] 3a 7a [2] 35 60 [2] 2b 7d [2] 29 7c [2] 32 7a [2] 2e 7d [2] 32 52 }

  condition:
    any of them
}