rule TTP_XOR_QUAD_CurrentVersionRun_7329 {
  strings:
    $key_7329 = { 20 46 [2] 04 48 [2] 2f 64 [2] 01 46 [2] 15 5d [2] 1a 47 [2] 04 5a [2] 06 5b [2] 1d 5d [2] 01 5a [2] 1d 75 }

  condition:
    any of them
}