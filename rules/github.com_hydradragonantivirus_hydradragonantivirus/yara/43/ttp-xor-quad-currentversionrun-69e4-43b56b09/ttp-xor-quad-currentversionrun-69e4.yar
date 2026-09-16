rule TTP_XOR_QUAD_CurrentVersionRun_69e4 {
  strings:
    $key_69e4 = { 3a 8b [2] 1e 85 [2] 35 a9 [2] 1b 8b [2] 0f 90 [2] 00 8a [2] 1e 97 [2] 1c 96 [2] 07 90 [2] 1b 97 [2] 07 b8 }

  condition:
    any of them
}