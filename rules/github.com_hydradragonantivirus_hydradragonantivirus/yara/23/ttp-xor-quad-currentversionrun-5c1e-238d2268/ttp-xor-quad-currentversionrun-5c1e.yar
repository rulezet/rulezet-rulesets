rule TTP_XOR_QUAD_CurrentVersionRun_5c1e {
  strings:
    $key_5c1e = { 0f 71 [2] 2b 7f [2] 00 53 [2] 2e 71 [2] 3a 6a [2] 35 70 [2] 2b 6d [2] 29 6c [2] 32 6a [2] 2e 6d [2] 32 42 }

  condition:
    any of them
}