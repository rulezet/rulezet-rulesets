rule TTP_XOR_QUAD_CurrentVersionRun_0744 {
  strings:
    $key_0744 = { 54 2b [2] 70 25 [2] 5b 09 [2] 75 2b [2] 61 30 [2] 6e 2a [2] 70 37 [2] 72 36 [2] 69 30 [2] 75 37 [2] 69 18 }

  condition:
    any of them
}