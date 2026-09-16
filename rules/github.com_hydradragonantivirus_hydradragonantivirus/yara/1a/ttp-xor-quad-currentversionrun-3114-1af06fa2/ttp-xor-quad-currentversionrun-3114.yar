rule TTP_XOR_QUAD_CurrentVersionRun_3114 {
  strings:
    $key_3114 = { 62 7b [2] 46 75 [2] 6d 59 [2] 43 7b [2] 57 60 [2] 58 7a [2] 46 67 [2] 44 66 [2] 5f 60 [2] 43 67 [2] 5f 48 }

  condition:
    any of them
}