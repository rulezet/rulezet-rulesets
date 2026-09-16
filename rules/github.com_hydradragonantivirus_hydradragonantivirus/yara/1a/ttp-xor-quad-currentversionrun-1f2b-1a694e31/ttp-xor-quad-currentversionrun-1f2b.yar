rule TTP_XOR_QUAD_CurrentVersionRun_1f2b {
  strings:
    $key_1f2b = { 4c 44 [2] 68 4a [2] 43 66 [2] 6d 44 [2] 79 5f [2] 76 45 [2] 68 58 [2] 6a 59 [2] 71 5f [2] 6d 58 [2] 71 77 }

  condition:
    any of them
}