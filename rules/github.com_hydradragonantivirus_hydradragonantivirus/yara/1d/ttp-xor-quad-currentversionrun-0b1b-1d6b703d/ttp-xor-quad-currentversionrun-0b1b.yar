rule TTP_XOR_QUAD_CurrentVersionRun_0b1b {
  strings:
    $key_0b1b = { 58 74 [2] 7c 7a [2] 57 56 [2] 79 74 [2] 6d 6f [2] 62 75 [2] 7c 68 [2] 7e 69 [2] 65 6f [2] 79 68 [2] 65 47 }

  condition:
    any of them
}