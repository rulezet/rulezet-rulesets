rule TTP_XOR_QUAD_CurrentVersionRun_7c29 {
  strings:
    $key_7c29 = { 2f 46 [2] 0b 48 [2] 20 64 [2] 0e 46 [2] 1a 5d [2] 15 47 [2] 0b 5a [2] 09 5b [2] 12 5d [2] 0e 5a [2] 12 75 }

  condition:
    any of them
}