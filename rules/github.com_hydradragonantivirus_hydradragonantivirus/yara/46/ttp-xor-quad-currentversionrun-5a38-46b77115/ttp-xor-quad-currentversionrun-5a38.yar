rule TTP_XOR_QUAD_CurrentVersionRun_5a38 {
  strings:
    $key_5a38 = { 09 57 [2] 2d 59 [2] 06 75 [2] 28 57 [2] 3c 4c [2] 33 56 [2] 2d 4b [2] 2f 4a [2] 34 4c [2] 28 4b [2] 34 64 }

  condition:
    any of them
}