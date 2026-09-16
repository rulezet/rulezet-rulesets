rule TTP_XOR_QUAD_CurrentVersionRun_637b {
  strings:
    $key_637b = { 30 14 [2] 14 1a [2] 3f 36 [2] 11 14 [2] 05 0f [2] 0a 15 [2] 14 08 [2] 16 09 [2] 0d 0f [2] 11 08 [2] 0d 27 }

  condition:
    any of them
}