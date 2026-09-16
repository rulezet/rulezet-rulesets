rule TTP_XOR_QUAD_CurrentVersionRun_036b {
  strings:
    $key_036b = { 50 04 [2] 74 0a [2] 5f 26 [2] 71 04 [2] 65 1f [2] 6a 05 [2] 74 18 [2] 76 19 [2] 6d 1f [2] 71 18 [2] 6d 37 }

  condition:
    any of them
}