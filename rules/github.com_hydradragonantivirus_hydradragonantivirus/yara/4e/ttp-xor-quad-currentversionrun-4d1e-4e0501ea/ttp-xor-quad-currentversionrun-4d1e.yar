rule TTP_XOR_QUAD_CurrentVersionRun_4d1e {
  strings:
    $key_4d1e = { 1e 71 [2] 3a 7f [2] 11 53 [2] 3f 71 [2] 2b 6a [2] 24 70 [2] 3a 6d [2] 38 6c [2] 23 6a [2] 3f 6d [2] 23 42 }

  condition:
    any of them
}