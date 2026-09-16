rule TTP_XOR_QUAD_CurrentVersionRun_773b {
  strings:
    $key_773b = { 24 54 [2] 00 5a [2] 2b 76 [2] 05 54 [2] 11 4f [2] 1e 55 [2] 00 48 [2] 02 49 [2] 19 4f [2] 05 48 [2] 19 67 }

  condition:
    any of them
}