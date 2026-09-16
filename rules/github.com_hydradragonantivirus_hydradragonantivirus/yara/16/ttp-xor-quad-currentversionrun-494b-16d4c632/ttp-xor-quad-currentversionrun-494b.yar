rule TTP_XOR_QUAD_CurrentVersionRun_494b {
  strings:
    $key_494b = { 1a 24 [2] 3e 2a [2] 15 06 [2] 3b 24 [2] 2f 3f [2] 20 25 [2] 3e 38 [2] 3c 39 [2] 27 3f [2] 3b 38 [2] 27 17 }

  condition:
    any of them
}