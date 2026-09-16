rule TTP_XOR_QUAD_CurrentVersionRun_5435 {
  strings:
    $key_5435 = { 07 5a [2] 23 54 [2] 08 78 [2] 26 5a [2] 32 41 [2] 3d 5b [2] 23 46 [2] 21 47 [2] 3a 41 [2] 26 46 [2] 3a 69 }

  condition:
    any of them
}