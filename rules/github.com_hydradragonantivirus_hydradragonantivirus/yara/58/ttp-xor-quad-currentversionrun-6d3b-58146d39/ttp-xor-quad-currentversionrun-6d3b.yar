rule TTP_XOR_QUAD_CurrentVersionRun_6d3b {
  strings:
    $key_6d3b = { 3e 54 [2] 1a 5a [2] 31 76 [2] 1f 54 [2] 0b 4f [2] 04 55 [2] 1a 48 [2] 18 49 [2] 03 4f [2] 1f 48 [2] 03 67 }

  condition:
    any of them
}