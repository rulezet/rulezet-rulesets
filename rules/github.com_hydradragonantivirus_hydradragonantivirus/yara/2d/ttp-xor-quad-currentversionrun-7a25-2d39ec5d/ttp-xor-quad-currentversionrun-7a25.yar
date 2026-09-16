rule TTP_XOR_QUAD_CurrentVersionRun_7a25 {
  strings:
    $key_7a25 = { 29 4a [2] 0d 44 [2] 26 68 [2] 08 4a [2] 1c 51 [2] 13 4b [2] 0d 56 [2] 0f 57 [2] 14 51 [2] 08 56 [2] 14 79 }

  condition:
    any of them
}