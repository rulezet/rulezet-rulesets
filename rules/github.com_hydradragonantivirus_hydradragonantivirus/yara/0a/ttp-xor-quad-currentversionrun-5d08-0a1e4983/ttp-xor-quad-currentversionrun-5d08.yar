rule TTP_XOR_QUAD_CurrentVersionRun_5d08 {
  strings:
    $key_5d08 = { 0e 67 [2] 2a 69 [2] 01 45 [2] 2f 67 [2] 3b 7c [2] 34 66 [2] 2a 7b [2] 28 7a [2] 33 7c [2] 2f 7b [2] 33 54 }

  condition:
    any of them
}