rule TTP_XOR_QUAD_CurrentVersionRun_074b {
  strings:
    $key_074b = { 54 24 [2] 70 2a [2] 5b 06 [2] 75 24 [2] 61 3f [2] 6e 25 [2] 70 38 [2] 72 39 [2] 69 3f [2] 75 38 [2] 69 17 }

  condition:
    any of them
}