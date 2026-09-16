rule TTP_XOR_QUAD_CurrentVersionRun_5408 {
  strings:
    $key_5408 = { 07 67 [2] 23 69 [2] 08 45 [2] 26 67 [2] 32 7c [2] 3d 66 [2] 23 7b [2] 21 7a [2] 3a 7c [2] 26 7b [2] 3a 54 }

  condition:
    any of them
}