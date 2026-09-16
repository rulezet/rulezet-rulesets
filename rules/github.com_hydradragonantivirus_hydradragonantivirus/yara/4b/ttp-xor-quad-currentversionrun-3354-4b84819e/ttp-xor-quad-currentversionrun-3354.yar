rule TTP_XOR_QUAD_CurrentVersionRun_3354 {
  strings:
    $key_3354 = { 60 3b [2] 44 35 [2] 6f 19 [2] 41 3b [2] 55 20 [2] 5a 3a [2] 44 27 [2] 46 26 [2] 5d 20 [2] 41 27 [2] 5d 08 }

  condition:
    any of them
}