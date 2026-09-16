rule TTP_XOR_QUAD_CurrentVersionRun_606b {
  strings:
    $key_606b = { 33 04 [2] 17 0a [2] 3c 26 [2] 12 04 [2] 06 1f [2] 09 05 [2] 17 18 [2] 15 19 [2] 0e 1f [2] 12 18 [2] 0e 37 }

  condition:
    any of them
}