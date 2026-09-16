rule TTP_XOR_QUAD_CurrentVersionRun_5608 {
  strings:
    $key_5608 = { 05 67 [2] 21 69 [2] 0a 45 [2] 24 67 [2] 30 7c [2] 3f 66 [2] 21 7b [2] 23 7a [2] 38 7c [2] 24 7b [2] 38 54 }

  condition:
    any of them
}