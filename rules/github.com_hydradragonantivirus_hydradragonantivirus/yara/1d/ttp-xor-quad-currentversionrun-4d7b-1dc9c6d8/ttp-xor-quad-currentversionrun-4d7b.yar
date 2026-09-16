rule TTP_XOR_QUAD_CurrentVersionRun_4d7b {
  strings:
    $key_4d7b = { 1e 14 [2] 3a 1a [2] 11 36 [2] 3f 14 [2] 2b 0f [2] 24 15 [2] 3a 08 [2] 38 09 [2] 23 0f [2] 3f 08 [2] 23 27 }

  condition:
    any of them
}