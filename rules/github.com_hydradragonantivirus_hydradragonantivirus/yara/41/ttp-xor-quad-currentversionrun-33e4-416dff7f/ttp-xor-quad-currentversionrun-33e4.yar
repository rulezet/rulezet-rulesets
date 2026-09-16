rule TTP_XOR_QUAD_CurrentVersionRun_33e4 {
  strings:
    $key_33e4 = { 60 8b [2] 44 85 [2] 6f a9 [2] 41 8b [2] 55 90 [2] 5a 8a [2] 44 97 [2] 46 96 [2] 5d 90 [2] 41 97 [2] 5d b8 }

  condition:
    any of them
}