rule TTP_XOR_QUAD_CurrentVersionRun_317b {
  strings:
    $key_317b = { 62 14 [2] 46 1a [2] 6d 36 [2] 43 14 [2] 57 0f [2] 58 15 [2] 46 08 [2] 44 09 [2] 5f 0f [2] 43 08 [2] 5f 27 }

  condition:
    any of them
}