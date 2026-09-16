rule TTP_XOR_QUAD_CurrentVersionRun_1f78 {
  strings:
    $key_1f78 = { 4c 17 [2] 68 19 [2] 43 35 [2] 6d 17 [2] 79 0c [2] 76 16 [2] 68 0b [2] 6a 0a [2] 71 0c [2] 6d 0b [2] 71 24 }

  condition:
    any of them
}