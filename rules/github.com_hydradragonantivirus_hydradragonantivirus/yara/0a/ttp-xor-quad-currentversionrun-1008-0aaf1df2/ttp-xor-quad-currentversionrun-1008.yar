rule TTP_XOR_QUAD_CurrentVersionRun_1008 {
  strings:
    $key_1008 = { 43 67 [2] 67 69 [2] 4c 45 [2] 62 67 [2] 76 7c [2] 79 66 [2] 67 7b [2] 65 7a [2] 7e 7c [2] 62 7b [2] 7e 54 }

  condition:
    any of them
}