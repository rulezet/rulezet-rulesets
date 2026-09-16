rule TTP_XOR_QUAD_CurrentVersionRun_1235 {
  strings:
    $key_1235 = { 41 5a [2] 65 54 [2] 4e 78 [2] 60 5a [2] 74 41 [2] 7b 5b [2] 65 46 [2] 67 47 [2] 7c 41 [2] 60 46 [2] 7c 69 }

  condition:
    any of them
}