rule TTP_XOR_QUAD_CurrentVersionRun_0b65 {
  strings:
    $key_0b65 = { 58 0a [2] 7c 04 [2] 57 28 [2] 79 0a [2] 6d 11 [2] 62 0b [2] 7c 16 [2] 7e 17 [2] 65 11 [2] 79 16 [2] 65 39 }

  condition:
    any of them
}