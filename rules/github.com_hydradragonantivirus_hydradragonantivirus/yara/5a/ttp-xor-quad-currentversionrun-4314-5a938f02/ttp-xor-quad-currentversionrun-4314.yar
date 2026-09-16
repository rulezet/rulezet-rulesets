rule TTP_XOR_QUAD_CurrentVersionRun_4314 {
  strings:
    $key_4314 = { 10 7b [2] 34 75 [2] 1f 59 [2] 31 7b [2] 25 60 [2] 2a 7a [2] 34 67 [2] 36 66 [2] 2d 60 [2] 31 67 [2] 2d 48 }

  condition:
    any of them
}