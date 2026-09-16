rule TTP_XOR_QUAD_CurrentVersionRun_1d17 {
  strings:
    $key_1d17 = { 4e 78 [2] 6a 76 [2] 41 5a [2] 6f 78 [2] 7b 63 [2] 74 79 [2] 6a 64 [2] 68 65 [2] 73 63 [2] 6f 64 [2] 73 4b }

  condition:
    any of them
}