rule TTP_XOR_QUAD_CurrentVersionRun_0747 {
  strings:
    $key_0747 = { 54 28 [2] 70 26 [2] 5b 0a [2] 75 28 [2] 61 33 [2] 6e 29 [2] 70 34 [2] 72 35 [2] 69 33 [2] 75 34 [2] 69 1b }

  condition:
    any of them
}