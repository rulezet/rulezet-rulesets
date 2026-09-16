rule TTP_XOR_QUAD_CurrentVersionRun_0b7b {
  strings:
    $key_0b7b = { 58 14 [2] 7c 1a [2] 57 36 [2] 79 14 [2] 6d 0f [2] 62 15 [2] 7c 08 [2] 7e 09 [2] 65 0f [2] 79 08 [2] 65 27 }

  condition:
    any of them
}