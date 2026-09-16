rule TTP_XOR_QUAD_CurrentVersionRun_5614 {
  strings:
    $key_5614 = { 05 7b [2] 21 75 [2] 0a 59 [2] 24 7b [2] 30 60 [2] 3f 7a [2] 21 67 [2] 23 66 [2] 38 60 [2] 24 67 [2] 38 48 }

  condition:
    any of them
}