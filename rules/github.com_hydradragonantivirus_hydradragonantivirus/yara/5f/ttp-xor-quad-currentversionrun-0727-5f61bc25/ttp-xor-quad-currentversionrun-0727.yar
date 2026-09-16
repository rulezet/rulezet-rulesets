rule TTP_XOR_QUAD_CurrentVersionRun_0727 {
  strings:
    $key_0727 = { 54 48 [2] 70 46 [2] 5b 6a [2] 75 48 [2] 61 53 [2] 6e 49 [2] 70 54 [2] 72 55 [2] 69 53 [2] 75 54 [2] 69 7b }

  condition:
    any of them
}