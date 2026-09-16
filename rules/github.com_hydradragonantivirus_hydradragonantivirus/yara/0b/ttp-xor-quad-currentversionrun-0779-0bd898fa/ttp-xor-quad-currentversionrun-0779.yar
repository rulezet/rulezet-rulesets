rule TTP_XOR_QUAD_CurrentVersionRun_0779 {
  strings:
    $key_0779 = { 54 16 [2] 70 18 [2] 5b 34 [2] 75 16 [2] 61 0d [2] 6e 17 [2] 70 0a [2] 72 0b [2] 69 0d [2] 75 0a [2] 69 25 }

  condition:
    any of them
}