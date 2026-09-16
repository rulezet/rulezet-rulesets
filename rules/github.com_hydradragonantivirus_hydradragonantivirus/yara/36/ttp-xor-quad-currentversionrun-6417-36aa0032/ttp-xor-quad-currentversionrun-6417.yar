rule TTP_XOR_QUAD_CurrentVersionRun_6417 {
  strings:
    $key_6417 = { 37 78 [2] 13 76 [2] 38 5a [2] 16 78 [2] 02 63 [2] 0d 79 [2] 13 64 [2] 11 65 [2] 0a 63 [2] 16 64 [2] 0a 4b }

  condition:
    any of them
}