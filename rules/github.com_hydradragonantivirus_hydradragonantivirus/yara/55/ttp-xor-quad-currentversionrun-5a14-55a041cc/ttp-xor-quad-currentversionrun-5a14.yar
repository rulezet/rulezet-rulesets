rule TTP_XOR_QUAD_CurrentVersionRun_5a14 {
  strings:
    $key_5a14 = { 09 7b [2] 2d 75 [2] 06 59 [2] 28 7b [2] 3c 60 [2] 33 7a [2] 2d 67 [2] 2f 66 [2] 34 60 [2] 28 67 [2] 34 48 }

  condition:
    any of them
}