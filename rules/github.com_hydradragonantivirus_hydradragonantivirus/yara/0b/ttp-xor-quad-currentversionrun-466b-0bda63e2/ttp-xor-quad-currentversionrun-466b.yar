rule TTP_XOR_QUAD_CurrentVersionRun_466b {
  strings:
    $key_466b = { 15 04 [2] 31 0a [2] 1a 26 [2] 34 04 [2] 20 1f [2] 2f 05 [2] 31 18 [2] 33 19 [2] 28 1f [2] 34 18 [2] 28 37 }

  condition:
    any of them
}