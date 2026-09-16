rule TTP_XOR_QUAD_CurrentVersionRun_1348 {
  strings:
    $key_1348 = { 40 27 [2] 64 29 [2] 4f 05 [2] 61 27 [2] 75 3c [2] 7a 26 [2] 64 3b [2] 66 3a [2] 7d 3c [2] 61 3b [2] 7d 14 }

  condition:
    any of them
}