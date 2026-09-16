rule TTP_XOR_QUAD_CurrentVersionRun_3309 {
  strings:
    $key_3309 = { 60 66 [2] 44 68 [2] 6f 44 [2] 41 66 [2] 55 7d [2] 5a 67 [2] 44 7a [2] 46 7b [2] 5d 7d [2] 41 7a [2] 5d 55 }

  condition:
    any of them
}