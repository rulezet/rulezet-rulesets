rule TTP_XOR_QUAD_CurrentVersionRun_137b {
  strings:
    $key_137b = { 40 14 [2] 64 1a [2] 4f 36 [2] 61 14 [2] 75 0f [2] 7a 15 [2] 64 08 [2] 66 09 [2] 7d 0f [2] 61 08 [2] 7d 27 }

  condition:
    any of them
}