rule TTP_XOR_QUAD_CurrentVersionRun_1a25 {
  strings:
    $key_1a25 = { 49 4a [2] 6d 44 [2] 46 68 [2] 68 4a [2] 7c 51 [2] 73 4b [2] 6d 56 [2] 6f 57 [2] 74 51 [2] 68 56 [2] 74 79 }

  condition:
    any of them
}