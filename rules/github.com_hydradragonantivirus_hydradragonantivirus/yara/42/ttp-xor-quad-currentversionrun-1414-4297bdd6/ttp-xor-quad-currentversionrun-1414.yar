rule TTP_XOR_QUAD_CurrentVersionRun_1414 {
  strings:
    $key_1414 = { 47 7b [2] 63 75 [2] 48 59 [2] 66 7b [2] 72 60 [2] 7d 7a [2] 63 67 [2] 61 66 [2] 7a 60 [2] 66 67 [2] 7a 48 }

  condition:
    any of them
}