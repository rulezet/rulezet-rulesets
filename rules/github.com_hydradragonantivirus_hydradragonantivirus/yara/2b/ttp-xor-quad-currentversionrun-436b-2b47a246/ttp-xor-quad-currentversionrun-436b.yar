rule TTP_XOR_QUAD_CurrentVersionRun_436b {
  strings:
    $key_436b = { 10 04 [2] 34 0a [2] 1f 26 [2] 31 04 [2] 25 1f [2] 2a 05 [2] 34 18 [2] 36 19 [2] 2d 1f [2] 31 18 [2] 2d 37 }

  condition:
    any of them
}