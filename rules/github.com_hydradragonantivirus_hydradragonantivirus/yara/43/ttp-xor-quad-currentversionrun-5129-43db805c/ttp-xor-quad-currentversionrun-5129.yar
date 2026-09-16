rule TTP_XOR_QUAD_CurrentVersionRun_5129 {
  strings:
    $key_5129 = { 02 46 [2] 26 48 [2] 0d 64 [2] 23 46 [2] 37 5d [2] 38 47 [2] 26 5a [2] 24 5b [2] 3f 5d [2] 23 5a [2] 3f 75 }

  condition:
    any of them
}