rule TTP_XOR_QUAD_CurrentVersionRun_3274 {
  strings:
    $key_3274 = { 61 1b [2] 45 15 [2] 6e 39 [2] 40 1b [2] 54 00 [2] 5b 1a [2] 45 07 [2] 47 06 [2] 5c 00 [2] 40 07 [2] 5c 28 }

  condition:
    any of them
}