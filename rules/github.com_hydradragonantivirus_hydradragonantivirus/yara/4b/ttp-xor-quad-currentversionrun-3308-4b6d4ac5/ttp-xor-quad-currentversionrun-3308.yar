rule TTP_XOR_QUAD_CurrentVersionRun_3308 {
  strings:
    $key_3308 = { 60 67 [2] 44 69 [2] 6f 45 [2] 41 67 [2] 55 7c [2] 5a 66 [2] 44 7b [2] 46 7a [2] 5d 7c [2] 41 7b [2] 5d 54 }

  condition:
    any of them
}