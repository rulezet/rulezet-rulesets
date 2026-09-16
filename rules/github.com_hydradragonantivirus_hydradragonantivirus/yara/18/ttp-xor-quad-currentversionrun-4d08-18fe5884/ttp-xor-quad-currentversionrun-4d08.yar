rule TTP_XOR_QUAD_CurrentVersionRun_4d08 {
  strings:
    $key_4d08 = { 1e 67 [2] 3a 69 [2] 11 45 [2] 3f 67 [2] 2b 7c [2] 24 66 [2] 3a 7b [2] 38 7a [2] 23 7c [2] 3f 7b [2] 23 54 }

  condition:
    any of them
}