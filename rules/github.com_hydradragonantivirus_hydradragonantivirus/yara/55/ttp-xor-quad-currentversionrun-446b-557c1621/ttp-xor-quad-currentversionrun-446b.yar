rule TTP_XOR_QUAD_CurrentVersionRun_446b {
  strings:
    $key_446b = { 17 04 [2] 33 0a [2] 18 26 [2] 36 04 [2] 22 1f [2] 2d 05 [2] 33 18 [2] 31 19 [2] 2a 1f [2] 36 18 [2] 2a 37 }

  condition:
    any of them
}