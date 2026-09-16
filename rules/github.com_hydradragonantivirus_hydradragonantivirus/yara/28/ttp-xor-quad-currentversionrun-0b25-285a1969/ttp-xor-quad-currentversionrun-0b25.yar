rule TTP_XOR_QUAD_CurrentVersionRun_0b25 {
  strings:
    $key_0b25 = { 58 4a [2] 7c 44 [2] 57 68 [2] 79 4a [2] 6d 51 [2] 62 4b [2] 7c 56 [2] 7e 57 [2] 65 51 [2] 79 56 [2] 65 79 }

  condition:
    any of them
}