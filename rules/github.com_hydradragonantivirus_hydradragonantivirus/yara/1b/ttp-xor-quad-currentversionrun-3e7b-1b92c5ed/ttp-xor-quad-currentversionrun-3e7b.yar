rule TTP_XOR_QUAD_CurrentVersionRun_3e7b {
  strings:
    $key_3e7b = { 6d 14 [2] 49 1a [2] 62 36 [2] 4c 14 [2] 58 0f [2] 57 15 [2] 49 08 [2] 4b 09 [2] 50 0f [2] 4c 08 [2] 50 27 }

  condition:
    any of them
}