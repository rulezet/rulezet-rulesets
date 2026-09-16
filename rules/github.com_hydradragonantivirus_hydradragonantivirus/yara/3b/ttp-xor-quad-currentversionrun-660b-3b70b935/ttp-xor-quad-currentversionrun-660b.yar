rule TTP_XOR_QUAD_CurrentVersionRun_660b {
  strings:
    $key_660b = { 35 64 [2] 11 6a [2] 3a 46 [2] 14 64 [2] 00 7f [2] 0f 65 [2] 11 78 [2] 13 79 [2] 08 7f [2] 14 78 [2] 08 57 }

  condition:
    any of them
}