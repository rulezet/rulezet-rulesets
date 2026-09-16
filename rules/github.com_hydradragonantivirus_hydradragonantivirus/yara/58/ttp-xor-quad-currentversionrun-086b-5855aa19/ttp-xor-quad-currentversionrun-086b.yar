rule TTP_XOR_QUAD_CurrentVersionRun_086b {
  strings:
    $key_086b = { 5b 04 [2] 7f 0a [2] 54 26 [2] 7a 04 [2] 6e 1f [2] 61 05 [2] 7f 18 [2] 7d 19 [2] 66 1f [2] 7a 18 [2] 66 37 }

  condition:
    any of them
}