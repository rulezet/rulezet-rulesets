rule TTP_XOR_QUAD_CurrentVersionRun_3247 {
  strings:
    $key_3247 = { 61 28 [2] 45 26 [2] 6e 0a [2] 40 28 [2] 54 33 [2] 5b 29 [2] 45 34 [2] 47 35 [2] 5c 33 [2] 40 34 [2] 5c 1b }

  condition:
    any of them
}