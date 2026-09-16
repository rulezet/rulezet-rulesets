rule TTP_XOR_QUAD_CurrentVersionRun_0b6b {
  strings:
    $key_0b6b = { 58 04 [2] 7c 0a [2] 57 26 [2] 79 04 [2] 6d 1f [2] 62 05 [2] 7c 18 [2] 7e 19 [2] 65 1f [2] 79 18 [2] 65 37 }

  condition:
    any of them
}