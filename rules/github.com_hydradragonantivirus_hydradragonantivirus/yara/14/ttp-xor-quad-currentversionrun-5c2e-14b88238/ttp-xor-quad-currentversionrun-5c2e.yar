rule TTP_XOR_QUAD_CurrentVersionRun_5c2e {
  strings:
    $key_5c2e = { 0f 41 [2] 2b 4f [2] 00 63 [2] 2e 41 [2] 3a 5a [2] 35 40 [2] 2b 5d [2] 29 5c [2] 32 5a [2] 2e 5d [2] 32 72 }

  condition:
    any of them
}