rule TTP_XOR_QUAD_CurrentVersionRun_5f38 {
  strings:
    $key_5f38 = { 0c 57 [2] 28 59 [2] 03 75 [2] 2d 57 [2] 39 4c [2] 36 56 [2] 28 4b [2] 2a 4a [2] 31 4c [2] 2d 4b [2] 31 64 }

  condition:
    any of them
}