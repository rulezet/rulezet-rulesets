rule TTP_XOR_QUAD_CurrentVersionRun_5105 {
  strings:
    $key_5105 = { 02 6a [2] 26 64 [2] 0d 48 [2] 23 6a [2] 37 71 [2] 38 6b [2] 26 76 [2] 24 77 [2] 3f 71 [2] 23 76 [2] 3f 59 }

  condition:
    any of them
}