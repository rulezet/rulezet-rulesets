rule TTP_XOR_QUAD_CurrentVersionRun_3319 {
  strings:
    $key_3319 = { 60 76 [2] 44 78 [2] 6f 54 [2] 41 76 [2] 55 6d [2] 5a 77 [2] 44 6a [2] 46 6b [2] 5d 6d [2] 41 6a [2] 5d 45 }

  condition:
    any of them
}