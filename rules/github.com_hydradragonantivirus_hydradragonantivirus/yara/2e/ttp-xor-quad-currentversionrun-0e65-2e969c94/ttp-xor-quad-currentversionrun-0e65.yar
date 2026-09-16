rule TTP_XOR_QUAD_CurrentVersionRun_0e65 {
  strings:
    $key_0e65 = { 5d 0a [2] 79 04 [2] 52 28 [2] 7c 0a [2] 68 11 [2] 67 0b [2] 79 16 [2] 7b 17 [2] 60 11 [2] 7c 16 [2] 60 39 }

  condition:
    any of them
}