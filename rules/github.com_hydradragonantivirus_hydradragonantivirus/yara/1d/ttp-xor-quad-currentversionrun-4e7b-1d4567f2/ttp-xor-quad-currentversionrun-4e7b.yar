rule TTP_XOR_QUAD_CurrentVersionRun_4e7b {
  strings:
    $key_4e7b = { 1d 14 [2] 39 1a [2] 12 36 [2] 3c 14 [2] 28 0f [2] 27 15 [2] 39 08 [2] 3b 09 [2] 20 0f [2] 3c 08 [2] 20 27 }

  condition:
    any of them
}