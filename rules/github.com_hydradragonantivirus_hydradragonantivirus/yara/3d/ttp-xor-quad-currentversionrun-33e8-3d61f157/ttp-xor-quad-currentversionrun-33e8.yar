rule TTP_XOR_QUAD_CurrentVersionRun_33e8 {
  strings:
    $key_33e8 = { 60 87 [2] 44 89 [2] 6f a5 [2] 41 87 [2] 55 9c [2] 5a 86 [2] 44 9b [2] 46 9a [2] 5d 9c [2] 41 9b [2] 5d b4 }

  condition:
    any of them
}