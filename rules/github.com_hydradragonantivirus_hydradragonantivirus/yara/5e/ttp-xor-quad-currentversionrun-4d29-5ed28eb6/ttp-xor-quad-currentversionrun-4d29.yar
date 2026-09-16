rule TTP_XOR_QUAD_CurrentVersionRun_4d29 {
  strings:
    $key_4d29 = { 1e 46 [2] 3a 48 [2] 11 64 [2] 3f 46 [2] 2b 5d [2] 24 47 [2] 3a 5a [2] 38 5b [2] 23 5d [2] 3f 5a [2] 23 75 }

  condition:
    any of them
}