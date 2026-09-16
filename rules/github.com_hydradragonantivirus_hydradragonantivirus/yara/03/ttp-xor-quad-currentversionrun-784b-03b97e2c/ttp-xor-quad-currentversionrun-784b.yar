rule TTP_XOR_QUAD_CurrentVersionRun_784b {
  strings:
    $key_784b = { 2b 24 [2] 0f 2a [2] 24 06 [2] 0a 24 [2] 1e 3f [2] 11 25 [2] 0f 38 [2] 0d 39 [2] 16 3f [2] 0a 38 [2] 16 17 }

  condition:
    any of them
}