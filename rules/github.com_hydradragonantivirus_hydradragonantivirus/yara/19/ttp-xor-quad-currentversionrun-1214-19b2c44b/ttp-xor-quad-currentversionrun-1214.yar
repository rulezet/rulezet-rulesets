rule TTP_XOR_QUAD_CurrentVersionRun_1214 {
  strings:
    $key_1214 = { 41 7b [2] 65 75 [2] 4e 59 [2] 60 7b [2] 74 60 [2] 7b 7a [2] 65 67 [2] 67 66 [2] 7c 60 [2] 60 67 [2] 7c 48 }

  condition:
    any of them
}