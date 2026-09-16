rule TTP_XOR_QUAD_CurrentVersionRun_1f47 {
  strings:
    $key_1f47 = { 4c 28 [2] 68 26 [2] 43 0a [2] 6d 28 [2] 79 33 [2] 76 29 [2] 68 34 [2] 6a 35 [2] 71 33 [2] 6d 34 [2] 71 1b }

  condition:
    any of them
}