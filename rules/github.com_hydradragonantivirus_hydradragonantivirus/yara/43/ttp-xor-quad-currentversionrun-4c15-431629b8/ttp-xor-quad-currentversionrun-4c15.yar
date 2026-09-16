rule TTP_XOR_QUAD_CurrentVersionRun_4c15 {
  strings:
    $key_4c15 = { 1f 7a [2] 3b 74 [2] 10 58 [2] 3e 7a [2] 2a 61 [2] 25 7b [2] 3b 66 [2] 39 67 [2] 22 61 [2] 3e 66 [2] 22 49 }

  condition:
    any of them
}