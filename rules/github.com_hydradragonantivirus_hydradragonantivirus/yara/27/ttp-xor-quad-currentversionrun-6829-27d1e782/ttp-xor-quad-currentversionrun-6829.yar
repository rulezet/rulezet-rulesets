rule TTP_XOR_QUAD_CurrentVersionRun_6829 {
  strings:
    $key_6829 = { 3b 46 [2] 1f 48 [2] 34 64 [2] 1a 46 [2] 0e 5d [2] 01 47 [2] 1f 5a [2] 1d 5b [2] 06 5d [2] 1a 5a [2] 06 75 }

  condition:
    any of them
}