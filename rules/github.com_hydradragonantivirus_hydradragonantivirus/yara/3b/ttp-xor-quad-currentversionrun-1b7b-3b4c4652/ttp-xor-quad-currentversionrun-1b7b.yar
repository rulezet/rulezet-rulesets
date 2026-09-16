rule TTP_XOR_QUAD_CurrentVersionRun_1b7b {
  strings:
    $key_1b7b = { 48 14 [2] 6c 1a [2] 47 36 [2] 69 14 [2] 7d 0f [2] 72 15 [2] 6c 08 [2] 6e 09 [2] 75 0f [2] 69 08 [2] 75 27 }

  condition:
    any of them
}