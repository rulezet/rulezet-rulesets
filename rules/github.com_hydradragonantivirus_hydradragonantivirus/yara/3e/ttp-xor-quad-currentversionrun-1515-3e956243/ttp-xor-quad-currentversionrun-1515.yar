rule TTP_XOR_QUAD_CurrentVersionRun_1515 {
  strings:
    $key_1515 = { 46 7a [2] 62 74 [2] 49 58 [2] 67 7a [2] 73 61 [2] 7c 7b [2] 62 66 [2] 60 67 [2] 7b 61 [2] 67 66 [2] 7b 49 }

  condition:
    any of them
}