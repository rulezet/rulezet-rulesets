rule TTP_XOR_QUAD_CurrentVersionRun_1a39 {
  strings:
    $key_1a39 = { 49 56 [2] 6d 58 [2] 46 74 [2] 68 56 [2] 7c 4d [2] 73 57 [2] 6d 4a [2] 6f 4b [2] 74 4d [2] 68 4a [2] 74 65 }

  condition:
    any of them
}