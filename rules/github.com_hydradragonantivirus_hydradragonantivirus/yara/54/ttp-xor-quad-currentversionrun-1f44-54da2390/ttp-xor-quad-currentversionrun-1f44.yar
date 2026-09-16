rule TTP_XOR_QUAD_CurrentVersionRun_1f44 {
  strings:
    $key_1f44 = { 4c 2b [2] 68 25 [2] 43 09 [2] 6d 2b [2] 79 30 [2] 76 2a [2] 68 37 [2] 6a 36 [2] 71 30 [2] 6d 37 [2] 71 18 }

  condition:
    any of them
}