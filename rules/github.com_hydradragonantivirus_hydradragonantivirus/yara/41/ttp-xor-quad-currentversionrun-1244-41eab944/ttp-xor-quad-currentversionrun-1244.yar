rule TTP_XOR_QUAD_CurrentVersionRun_1244 {
  strings:
    $key_1244 = { 41 2b [2] 65 25 [2] 4e 09 [2] 60 2b [2] 74 30 [2] 7b 2a [2] 65 37 [2] 67 36 [2] 7c 30 [2] 60 37 [2] 7c 18 }

  condition:
    any of them
}