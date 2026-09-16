rule TTP_XOR_QUAD_CurrentVersionRun_1d3b {
  strings:
    $key_1d3b = { 4e 54 [2] 6a 5a [2] 41 76 [2] 6f 54 [2] 7b 4f [2] 74 55 [2] 6a 48 [2] 68 49 [2] 73 4f [2] 6f 48 [2] 73 67 }

  condition:
    any of them
}