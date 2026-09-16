rule TTP_XOR_QUAD_CurrentVersionRun_33f9 {
  strings:
    $key_33f9 = { 60 96 [2] 44 98 [2] 6f b4 [2] 41 96 [2] 55 8d [2] 5a 97 [2] 44 8a [2] 46 8b [2] 5d 8d [2] 41 8a [2] 5d a5 }

  condition:
    any of them
}