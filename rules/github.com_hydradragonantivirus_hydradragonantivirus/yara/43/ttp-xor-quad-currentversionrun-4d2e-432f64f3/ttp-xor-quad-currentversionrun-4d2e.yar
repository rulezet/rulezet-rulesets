rule TTP_XOR_QUAD_CurrentVersionRun_4d2e {
  strings:
    $key_4d2e = { 1e 41 [2] 3a 4f [2] 11 63 [2] 3f 41 [2] 2b 5a [2] 24 40 [2] 3a 5d [2] 38 5c [2] 23 5a [2] 3f 5d [2] 23 72 }

  condition:
    any of them
}