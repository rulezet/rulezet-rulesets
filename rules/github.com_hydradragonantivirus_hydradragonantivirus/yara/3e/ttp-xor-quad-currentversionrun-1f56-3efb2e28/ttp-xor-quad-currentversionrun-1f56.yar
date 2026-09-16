rule TTP_XOR_QUAD_CurrentVersionRun_1f56 {
  strings:
    $key_1f56 = { 4c 39 [2] 68 37 [2] 43 1b [2] 6d 39 [2] 79 22 [2] 76 38 [2] 68 25 [2] 6a 24 [2] 71 22 [2] 6d 25 [2] 71 0a }

  condition:
    any of them
}