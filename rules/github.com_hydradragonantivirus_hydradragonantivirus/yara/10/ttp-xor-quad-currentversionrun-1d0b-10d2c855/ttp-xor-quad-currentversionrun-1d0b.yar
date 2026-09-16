rule TTP_XOR_QUAD_CurrentVersionRun_1d0b {
  strings:
    $key_1d0b = { 4e 64 [2] 6a 6a [2] 41 46 [2] 6f 64 [2] 7b 7f [2] 74 65 [2] 6a 78 [2] 68 79 [2] 73 7f [2] 6f 78 [2] 73 57 }

  condition:
    any of them
}