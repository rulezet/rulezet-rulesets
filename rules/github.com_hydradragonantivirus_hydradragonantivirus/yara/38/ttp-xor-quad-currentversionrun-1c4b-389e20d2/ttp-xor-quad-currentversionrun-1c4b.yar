rule TTP_XOR_QUAD_CurrentVersionRun_1c4b {
  strings:
    $key_1c4b = { 4f 24 [2] 6b 2a [2] 40 06 [2] 6e 24 [2] 7a 3f [2] 75 25 [2] 6b 38 [2] 69 39 [2] 72 3f [2] 6e 38 [2] 72 17 }

  condition:
    any of them
}