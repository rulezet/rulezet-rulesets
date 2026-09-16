rule TTP_XOR_QUAD_CurrentVersionRun_1ae4 {
  strings:
    $key_1ae4 = { 49 8b [2] 6d 85 [2] 46 a9 [2] 68 8b [2] 7c 90 [2] 73 8a [2] 6d 97 [2] 6f 96 [2] 74 90 [2] 68 97 [2] 74 b8 }

  condition:
    any of them
}