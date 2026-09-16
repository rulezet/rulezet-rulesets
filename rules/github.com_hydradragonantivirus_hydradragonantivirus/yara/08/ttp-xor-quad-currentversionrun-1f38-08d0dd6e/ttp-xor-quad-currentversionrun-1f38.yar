rule TTP_XOR_QUAD_CurrentVersionRun_1f38 {
  strings:
    $key_1f38 = { 4c 57 [2] 68 59 [2] 43 75 [2] 6d 57 [2] 79 4c [2] 76 56 [2] 68 4b [2] 6a 4a [2] 71 4c [2] 6d 4b [2] 71 64 }

  condition:
    any of them
}