rule TTP_XOR_QUAD_CurrentVersionRun_0756 {
  strings:
    $key_0756 = { 54 39 [2] 70 37 [2] 5b 1b [2] 75 39 [2] 61 22 [2] 6e 38 [2] 70 25 [2] 72 24 [2] 69 22 [2] 75 25 [2] 69 0a }

  condition:
    any of them
}