rule TTP_XOR_QUAD_CurrentVersionRun_5144 {
  strings:
    $key_5144 = { 02 2b [2] 26 25 [2] 0d 09 [2] 23 2b [2] 37 30 [2] 38 2a [2] 26 37 [2] 24 36 [2] 3f 30 [2] 23 37 [2] 3f 18 }

  condition:
    any of them
}