rule TTP_XOR_QUAD_CurrentVersionRun_075a {
  strings:
    $key_075a = { 54 35 [2] 70 3b [2] 5b 17 [2] 75 35 [2] 61 2e [2] 6e 34 [2] 70 29 [2] 72 28 [2] 69 2e [2] 75 29 [2] 69 06 }

  condition:
    any of them
}