rule TTP_XOR_QUAD_CurrentVersionRun_5428 {
  strings:
    $key_5428 = { 07 47 [2] 23 49 [2] 08 65 [2] 26 47 [2] 32 5c [2] 3d 46 [2] 23 5b [2] 21 5a [2] 3a 5c [2] 26 5b [2] 3a 74 }

  condition:
    any of them
}