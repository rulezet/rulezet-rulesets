rule TTP_XOR_QUAD_CurrentVersionRun_1f7b {
  strings:
    $key_1f7b = { 4c 14 [2] 68 1a [2] 43 36 [2] 6d 14 [2] 79 0f [2] 76 15 [2] 68 08 [2] 6a 09 [2] 71 0f [2] 6d 08 [2] 71 27 }

  condition:
    any of them
}