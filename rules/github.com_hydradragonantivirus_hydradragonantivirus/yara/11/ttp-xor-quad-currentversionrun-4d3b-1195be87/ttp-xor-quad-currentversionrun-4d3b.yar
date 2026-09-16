rule TTP_XOR_QUAD_CurrentVersionRun_4d3b {
  strings:
    $key_4d3b = { 1e 54 [2] 3a 5a [2] 11 76 [2] 3f 54 [2] 2b 4f [2] 24 55 [2] 3a 48 [2] 38 49 [2] 23 4f [2] 3f 48 [2] 23 67 }

  condition:
    any of them
}