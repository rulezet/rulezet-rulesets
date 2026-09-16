rule TTP_XOR_QUAD_CurrentVersionRun_6308 {
  strings:
    $key_6308 = { 30 67 [2] 14 69 [2] 3f 45 [2] 11 67 [2] 05 7c [2] 0a 66 [2] 14 7b [2] 16 7a [2] 0d 7c [2] 11 7b [2] 0d 54 }

  condition:
    any of them
}