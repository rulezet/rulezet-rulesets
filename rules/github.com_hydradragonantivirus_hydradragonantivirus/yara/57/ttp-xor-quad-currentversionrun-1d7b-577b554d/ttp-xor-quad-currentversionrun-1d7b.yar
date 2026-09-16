rule TTP_XOR_QUAD_CurrentVersionRun_1d7b {
  strings:
    $key_1d7b = { 4e 14 [2] 6a 1a [2] 41 36 [2] 6f 14 [2] 7b 0f [2] 74 15 [2] 6a 08 [2] 68 09 [2] 73 0f [2] 6f 08 [2] 73 27 }

  condition:
    any of them
}