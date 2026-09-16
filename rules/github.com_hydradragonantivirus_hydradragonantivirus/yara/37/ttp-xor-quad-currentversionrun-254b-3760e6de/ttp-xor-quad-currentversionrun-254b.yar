rule TTP_XOR_QUAD_CurrentVersionRun_254b {
  strings:
    $key_254b = { 76 24 [2] 52 2a [2] 79 06 [2] 57 24 [2] 43 3f [2] 4c 25 [2] 52 38 [2] 50 39 [2] 4b 3f [2] 57 38 [2] 4b 17 }

  condition:
    any of them
}