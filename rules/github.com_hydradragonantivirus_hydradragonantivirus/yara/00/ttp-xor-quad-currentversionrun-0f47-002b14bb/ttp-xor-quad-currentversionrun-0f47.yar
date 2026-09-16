rule TTP_XOR_QUAD_CurrentVersionRun_0f47 {
  strings:
    $key_0f47 = { 5c 28 [2] 78 26 [2] 53 0a [2] 7d 28 [2] 69 33 [2] 66 29 [2] 78 34 [2] 7a 35 [2] 61 33 [2] 7d 34 [2] 61 1b }

  condition:
    any of them
}