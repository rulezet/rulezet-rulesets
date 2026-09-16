rule TTP_XOR_QUAD_CurrentVersionRun_2809 {
  strings:
    $key_2809 = { 7b 66 [2] 5f 68 [2] 74 44 [2] 5a 66 [2] 4e 7d [2] 41 67 [2] 5f 7a [2] 5d 7b [2] 46 7d [2] 5a 7a [2] 46 55 }

  condition:
    any of them
}