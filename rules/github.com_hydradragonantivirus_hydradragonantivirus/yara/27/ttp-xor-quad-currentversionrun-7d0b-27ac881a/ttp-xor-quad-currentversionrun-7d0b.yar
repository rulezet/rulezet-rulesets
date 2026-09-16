rule TTP_XOR_QUAD_CurrentVersionRun_7d0b {
  strings:
    $key_7d0b = { 2e 64 [2] 0a 6a [2] 21 46 [2] 0f 64 [2] 1b 7f [2] 14 65 [2] 0a 78 [2] 08 79 [2] 13 7f [2] 0f 78 [2] 13 57 }

  condition:
    any of them
}