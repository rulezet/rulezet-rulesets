rule TTP_XOR_QUAD_CurrentVersionRun_3257 {
  strings:
    $key_3257 = { 61 38 [2] 45 36 [2] 6e 1a [2] 40 38 [2] 54 23 [2] 5b 39 [2] 45 24 [2] 47 25 [2] 5c 23 [2] 40 24 [2] 5c 0b }

  condition:
    any of them
}