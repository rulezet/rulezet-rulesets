rule TTP_XOR_QUAD_CurrentVersionRun_6429 {
  strings:
    $key_6429 = { 37 46 [2] 13 48 [2] 38 64 [2] 16 46 [2] 02 5d [2] 0d 47 [2] 13 5a [2] 11 5b [2] 0a 5d [2] 16 5a [2] 0a 75 }

  condition:
    any of them
}