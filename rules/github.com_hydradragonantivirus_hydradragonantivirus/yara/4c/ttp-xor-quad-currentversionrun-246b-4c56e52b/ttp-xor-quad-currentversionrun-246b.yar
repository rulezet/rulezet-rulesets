rule TTP_XOR_QUAD_CurrentVersionRun_246b {
  strings:
    $key_246b = { 77 04 [2] 53 0a [2] 78 26 [2] 56 04 [2] 42 1f [2] 4d 05 [2] 53 18 [2] 51 19 [2] 4a 1f [2] 56 18 [2] 4a 37 }

  condition:
    any of them
}