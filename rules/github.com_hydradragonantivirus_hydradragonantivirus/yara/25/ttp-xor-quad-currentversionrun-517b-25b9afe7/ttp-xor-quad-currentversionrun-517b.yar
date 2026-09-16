rule TTP_XOR_QUAD_CurrentVersionRun_517b {
  strings:
    $key_517b = { 02 14 [2] 26 1a [2] 0d 36 [2] 23 14 [2] 37 0f [2] 38 15 [2] 26 08 [2] 24 09 [2] 3f 0f [2] 23 08 [2] 3f 27 }

  condition:
    any of them
}