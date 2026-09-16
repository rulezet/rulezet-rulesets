rule TTP_XOR_QUAD_CurrentVersionRun_636b {
  strings:
    $key_636b = { 30 04 [2] 14 0a [2] 3f 26 [2] 11 04 [2] 05 1f [2] 0a 05 [2] 14 18 [2] 16 19 [2] 0d 1f [2] 11 18 [2] 0d 37 }

  condition:
    any of them
}