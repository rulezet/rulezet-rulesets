rule TTP_XOR_QUAD_CurrentVersionRun_5f7b {
  strings:
    $key_5f7b = { 0c 14 [2] 28 1a [2] 03 36 [2] 2d 14 [2] 39 0f [2] 36 15 [2] 28 08 [2] 2a 09 [2] 31 0f [2] 2d 08 [2] 31 27 }

  condition:
    any of them
}