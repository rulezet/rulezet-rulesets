rule TTP_XOR_QUAD_CurrentVersionRun_5429 {
  strings:
    $key_5429 = { 07 46 [2] 23 48 [2] 08 64 [2] 26 46 [2] 32 5d [2] 3d 47 [2] 23 5a [2] 21 5b [2] 3a 5d [2] 26 5a [2] 3a 75 }

  condition:
    any of them
}