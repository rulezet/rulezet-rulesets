rule TTP_XOR_QUAD_CurrentVersionRun_1c7b {
  strings:
    $key_1c7b = { 4f 14 [2] 6b 1a [2] 40 36 [2] 6e 14 [2] 7a 0f [2] 75 15 [2] 6b 08 [2] 69 09 [2] 72 0f [2] 6e 08 [2] 72 27 }

  condition:
    any of them
}