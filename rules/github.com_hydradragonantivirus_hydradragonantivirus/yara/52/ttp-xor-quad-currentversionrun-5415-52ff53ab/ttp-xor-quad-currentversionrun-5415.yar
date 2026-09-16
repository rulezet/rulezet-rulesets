rule TTP_XOR_QUAD_CurrentVersionRun_5415 {
  strings:
    $key_5415 = { 07 7a [2] 23 74 [2] 08 58 [2] 26 7a [2] 32 61 [2] 3d 7b [2] 23 66 [2] 21 67 [2] 3a 61 [2] 26 66 [2] 3a 49 }

  condition:
    any of them
}