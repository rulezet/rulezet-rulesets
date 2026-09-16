rule TTP_XOR_QUAD_CurrentVersionRun_3324 {
  strings:
    $key_3324 = { 60 4b [2] 44 45 [2] 6f 69 [2] 41 4b [2] 55 50 [2] 5a 4a [2] 44 57 [2] 46 56 [2] 5d 50 [2] 41 57 [2] 5d 78 }

  condition:
    any of them
}