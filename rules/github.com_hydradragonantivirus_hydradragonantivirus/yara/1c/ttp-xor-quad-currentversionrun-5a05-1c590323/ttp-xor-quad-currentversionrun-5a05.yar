rule TTP_XOR_QUAD_CurrentVersionRun_5a05 {
  strings:
    $key_5a05 = { 09 6a [2] 2d 64 [2] 06 48 [2] 28 6a [2] 3c 71 [2] 33 6b [2] 2d 76 [2] 2f 77 [2] 34 71 [2] 28 76 [2] 34 59 }

  condition:
    any of them
}