rule TTP_XOR_QUAD_CurrentVersionRun_0be4 {
  strings:
    $key_0be4 = { 58 8b [2] 7c 85 [2] 57 a9 [2] 79 8b [2] 6d 90 [2] 62 8a [2] 7c 97 [2] 7e 96 [2] 65 90 [2] 79 97 [2] 65 b8 }

  condition:
    any of them
}