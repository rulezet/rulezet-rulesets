rule TTP_XOR_QUAD_CurrentVersionRun_0b06 {
  strings:
    $key_0b06 = { 58 69 [2] 7c 67 [2] 57 4b [2] 79 69 [2] 6d 72 [2] 62 68 [2] 7c 75 [2] 7e 74 [2] 65 72 [2] 79 75 [2] 65 5a }

  condition:
    any of them
}