rule TTP_XOR_QUAD_CurrentVersionRun_056b {
  strings:
    $key_056b = { 56 04 [2] 72 0a [2] 59 26 [2] 77 04 [2] 63 1f [2] 6c 05 [2] 72 18 [2] 70 19 [2] 6b 1f [2] 77 18 [2] 6b 37 }

  condition:
    any of them
}